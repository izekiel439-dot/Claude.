<#
    Checks.Defender.ps1 - Defender health, tampering and OS hardening posture.

    The premise of this module: Defender will never tell you that Defender has
    been weakened. Exclusion paths, disabled ASR rules, downgraded UAC and
    WDigest credential caching are all *configuration*, so they generate no
    detection - but they are exactly what an attacker changes first.
#>

$script:DefenderCategory = 'Defender & Hardening'

# Attack Surface Reduction rules, by GUID. Action 1 = Block, 2 = Audit, 6 = Warn.
$script:AsrRules = @{
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office applications from creating child processes'
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email and webmail'
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executables unless they meet prevalence/age criteria'
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JS/VBScript from launching downloaded content'
    '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office applications from creating executable content'
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office applications from injecting into other processes'
    '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication apps from creating child processes'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations from PSExec and WMI commands'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted/unsigned processes running from USB'
    'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Block use of copied or impersonated system tools'
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'
}

function Test-DefenderStatus {
    Write-ScanLog -Message 'Defender engine status' -Level 'Step'

    $status = $null
    try { $status = Get-MpComputerStatus -ErrorAction Stop } catch { }

    if (-not $status) {
        Add-Finding -Category $script:DefenderCategory -Check 'DefenderStatus' -Severity 'High' `
                    -Title 'Microsoft Defender status could not be read' `
                    -Detail 'Get-MpComputerStatus failed. Either Defender has been removed/replaced by another AV product, the Defender service is not running, or the scan is not elevated.' `
                    -Recommendation 'Run this scanner from an elevated PowerShell prompt. If it still fails, check that the WinDefend service is running and that a third-party AV has not disabled it.' `
                    -Evidence ([ordered]@{ 'Elevated scan' = (Test-IsElevated) })
        return
    }

    $toggles = @(
        @{ Name = 'RealTimeProtectionEnabled'; Label = 'Real-time protection';  Severity = 'Critical' }
        @{ Name = 'AntivirusEnabled';          Label = 'Antivirus engine';       Severity = 'Critical' }
        @{ Name = 'AntispywareEnabled';        Label = 'Antispyware engine';     Severity = 'Critical' }
        @{ Name = 'BehaviorMonitorEnabled';    Label = 'Behaviour monitoring';   Severity = 'High' }
        @{ Name = 'IoavProtectionEnabled';     Label = 'Downloaded file scanning'; Severity = 'High' }
        @{ Name = 'OnAccessProtectionEnabled'; Label = 'On-access protection';   Severity = 'High' }
        @{ Name = 'NISEnabled';                Label = 'Network inspection';     Severity = 'Medium' }
    )

    foreach ($toggle in $toggles) {
        if (-not $status.PSObject.Properties[$toggle.Name]) { continue }
        if ($status.($toggle.Name)) { continue }

        Add-Finding -Category $script:DefenderCategory -Check 'DefenderStatus' -Severity $toggle.Severity `
                    -Title "$($toggle.Label) is disabled" `
                    -Detail "Defender reports $($toggle.Name) = False. If you did not turn this off yourself, something else did." `
                    -Recommendation 'Re-enable in Windows Security > Virus & threat protection. If the setting reverts or is greyed out, a policy or a running process is holding it off - investigate before trusting the machine.' `
                    -Evidence ([ordered]@{ 'Setting' = $toggle.Name; 'Value' = 'False' })
    }

    if ($status.PSObject.Properties['IsTamperProtected'] -and -not $status.IsTamperProtected) {
        Add-Finding -Category $script:DefenderCategory -Check 'DefenderStatus' -Severity 'High' `
                    -Title 'Tamper Protection is off' `
                    -Detail 'Without Tamper Protection, any process running as administrator can silently disable Defender features or add exclusions.' `
                    -Recommendation 'Turn on Windows Security > Virus & threat protection > Manage settings > Tamper Protection.' `
                    -Evidence ([ordered]@{ 'IsTamperProtected' = 'False' })
    }

    if ($status.PSObject.Properties['AntivirusSignatureAge']) {
        $age = [int]$status.AntivirusSignatureAge
        if ($age -gt 7) {
            $severity = if ($age -gt 30) { 'High' } else { 'Medium' }
            Add-Finding -Category $script:DefenderCategory -Check 'DefenderStatus' -Severity $severity `
                        -Title "Defender signatures are $age days old" `
                        -Detail 'Stale definitions usually mean update delivery is broken or has been deliberately blocked (a common step after an initial compromise).' `
                        -Recommendation 'Run Update-MpSignature. If it fails, check the hosts file and proxy findings in this report - update endpoints are a frequent blackhole target.' `
                        -Evidence ([ordered]@{
                            'Signature age (days)' = $age
                            'Last update'          = $status.AntivirusSignatureLastUpdated
                            'Signature version'    = $status.AntivirusSignatureVersion
                        })
        }
    }

    $lastScan = $null
    foreach ($property in @('FullScanEndTime','QuickScanEndTime')) {
        if ($status.PSObject.Properties[$property] -and $status.$property) {
            if (-not $lastScan -or $status.$property -gt $lastScan) { $lastScan = $status.$property }
        }
    }
    if (-not $lastScan) {
        Add-Finding -Category $script:DefenderCategory -Check 'DefenderStatus' -Severity 'Low' `
                    -Title 'No completed Defender scan is recorded' `
                    -Detail 'Neither a quick nor a full scan has a recorded end time.' `
                    -Recommendation 'Run Start-MpScan -ScanType QuickScan to establish a baseline.' `
                    -Evidence ([ordered]@{ 'FullScanEndTime' = $status.FullScanEndTime; 'QuickScanEndTime' = $status.QuickScanEndTime })
    }
    elseif (((Get-Date) - $lastScan).TotalDays -gt 14) {
        Add-Finding -Category $script:DefenderCategory -Check 'DefenderStatus' -Severity 'Low' `
                    -Title "Last Defender scan was $([int](((Get-Date) - $lastScan).TotalDays)) days ago" `
                    -Detail 'Real-time protection covers most cases, but a periodic full scan catches dormant files written before a signature existed.' `
                    -Recommendation 'Run Start-MpScan -ScanType FullScan.' `
                    -Evidence ([ordered]@{ 'Last scan' = $lastScan })
    }
}

function Test-DefenderExclusions {
    <#
        .SYNOPSIS
        Exclusions are the single highest-value tampering target: adding one is
        a supported operation that produces no alert, and everything inside it
        becomes invisible to Defender permanently.
    #>
    Write-ScanLog -Message 'Defender exclusions' -Level 'Step'

    $preference = $null
    try { $preference = Get-MpPreference -ErrorAction Stop } catch { return }

    $exclusionTypes = @(
        @{ Property = 'ExclusionPath';      Label = 'path' }
        @{ Property = 'ExclusionProcess';   Label = 'process' }
        @{ Property = 'ExclusionExtension'; Label = 'extension' }
        @{ Property = 'ExclusionIpAddress'; Label = 'IP address' }
    )

    foreach ($type in $exclusionTypes) {
        if (-not $preference.PSObject.Properties[$type.Property]) { continue }
        $values = @($preference.($type.Property)) | Where-Object { $_ }
        if ($values.Count -eq 0) { continue }

        foreach ($value in $values) {
            $text = "$value"
            $severity = 'Medium'
            $notes = New-Object System.Collections.ArrayList

            # An exclusion whose scope is enormous is functionally "AV off".
            if ($text -match '^[A-Za-z]:\\?$' -or $text -match '^[A-Za-z]:\\(Users|Windows|ProgramData|Program Files)\\?$' -or $text -eq '*') {
                $severity = 'Critical'
                $null = $notes.Add('This exclusion covers a top-level directory, which removes Defender coverage from a huge portion of the disk')
            }
            elseif ($text -match '\\Temp\\?$|\\AppData\\?|\\Downloads\\?$|\\Public\\?$') {
                $severity = 'High'
                $null = $notes.Add('This exclusion covers a directory malware routinely writes to')
            }
            if ($type.Property -eq 'ExclusionExtension' -and $text -match '^\.?(exe|dll|ps1|js|vbs|bat|cmd|scr)$') {
                $severity = 'Critical'
                $null = $notes.Add('Excluding an executable file type disables scanning of that type everywhere on the machine')
            }
            if ($type.Property -eq 'ExclusionProcess') {
                $null = $notes.Add('Files touched by this process are not scanned while it runs')
            }

            $detail = "Defender is configured to skip this $($type.Label). "
            if ($notes.Count -gt 0) { $detail += ($notes -join '. ') + '. ' }
            $detail += 'Exclusions are invisible in normal Defender reporting and are commonly added by an attacker to create a safe staging area.'

            Add-Finding -Category $script:DefenderCategory -Check 'DefenderExclusions' -Severity $severity `
                        -Title "Defender exclusion ($($type.Label)): $text" `
                        -Detail $detail `
                        -Recommendation "If you did not add this yourself, remove it with Remove-MpPreference -$($type.Property) '$text' and then run a full scan of the excluded location." `
                        -Evidence ([ordered]@{ 'Exclusion type' = $type.Property; 'Value' = $text })
        }
    }

    # Feature-level opt-outs stored in preferences.
    $disableFlags = @(
        @{ Name = 'DisableRealtimeMonitoring';   Label = 'Real-time monitoring';        Severity = 'Critical' }
        @{ Name = 'DisableBehaviorMonitoring';   Label = 'Behaviour monitoring';        Severity = 'High' }
        @{ Name = 'DisableScriptScanning';       Label = 'Script scanning';             Severity = 'High' }
        @{ Name = 'DisableArchiveScanning';      Label = 'Archive scanning';            Severity = 'Medium' }
        @{ Name = 'DisableIOAVProtection';       Label = 'Downloaded file scanning';    Severity = 'High' }
        @{ Name = 'DisableRemovableDriveScanning'; Label = 'Removable drive scanning';  Severity = 'Low' }
        @{ Name = 'DisableBlockAtFirstSeen';     Label = 'Block at first sight';        Severity = 'High' }
    )
    foreach ($flag in $disableFlags) {
        if (-not $preference.PSObject.Properties[$flag.Name]) { continue }
        if (-not $preference.($flag.Name)) { continue }

        Add-Finding -Category $script:DefenderCategory -Check 'DefenderExclusions' -Severity $flag.Severity `
                    -Title "$($flag.Label) has been switched off in Defender preferences" `
                    -Detail "Get-MpPreference reports $($flag.Name) = True." `
                    -Recommendation "Re-enable with Set-MpPreference -$($flag.Name) `$false" `
                    -Evidence ([ordered]@{ 'Preference' = $flag.Name; 'Value' = 'True' })
    }

    if ($preference.PSObject.Properties['MAPSReporting'] -and [int]$preference.MAPSReporting -eq 0) {
        Add-Finding -Category $script:DefenderCategory -Check 'DefenderExclusions' -Severity 'Medium' `
                    -Title 'Cloud-delivered protection (MAPS) is disabled' `
                    -Detail 'Without cloud lookups, Defender is limited to local signatures and loses most of its ability to catch novel samples.' `
                    -Recommendation 'Set-MpPreference -MAPSReporting Advanced' `
                    -Evidence ([ordered]@{ 'MAPSReporting' = $preference.MAPSReporting })
    }

    if ($preference.PSObject.Properties['PUAProtection'] -and [int]$preference.PUAProtection -eq 0) {
        Add-Finding -Category $script:DefenderCategory -Check 'DefenderExclusions' -Severity 'Low' `
                    -Title 'Potentially Unwanted Application protection is off' `
                    -Detail 'PUA protection covers adware, bundleware and many "grey" remote-access tools that the antivirus engine deliberately does not treat as malware.' `
                    -Recommendation 'Set-MpPreference -PUAProtection Enabled' `
                    -Evidence ([ordered]@{ 'PUAProtection' = $preference.PUAProtection })
    }
}

function Test-AsrRules {
    Write-ScanLog -Message 'Attack Surface Reduction rules' -Level 'Step'

    $preference = $null
    try { $preference = Get-MpPreference -ErrorAction Stop } catch { return }
    if (-not $preference.PSObject.Properties['AttackSurfaceReductionRules_Ids']) { return }

    $ids     = @($preference.AttackSurfaceReductionRules_Ids)
    $actions = @($preference.AttackSurfaceReductionRules_Actions)

    $configured = @{}
    for ($i = 0; $i -lt $ids.Count; $i++) {
        if (-not $ids[$i]) { continue }
        $action = if ($i -lt $actions.Count) { [int]$actions[$i] } else { 0 }
        $configured["$($ids[$i])".ToLowerInvariant()] = $action
    }

    # The rules that matter most for a home/workstation threat model.
    $highValue = @(
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'  # LSASS credential theft
        'e6db77e5-3df2-4cf1-b95a-636979351e5b'  # WMI persistence
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a'  # Office child processes
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc'  # Obfuscated scripts
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'  # Executable content from email
        'd3e037e1-3eb8-44c8-a917-57927947596d'  # JS/VBS launching downloads
        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'  # Win32 calls from macros
        '3b576869-a4ec-4529-8536-b80a7769e899'  # Office creating executables
        'c1db55ab-c21a-4637-bb3f-a12568109d35'  # Ransomware protection
        '56a863a9-875e-4185-98a7-b882c64b5ce5'  # Vulnerable signed drivers
    )

    $notBlocking = New-Object System.Collections.ArrayList
    foreach ($id in $highValue) {
        $action = if ($configured.ContainsKey($id)) { $configured[$id] } else { 0 }
        if ($action -eq 1) { continue }
        $state = switch ($action) { 2 { 'Audit only' } 6 { 'Warn only' } default { 'Not configured' } }
        $null = $notBlocking.Add("$($script:AsrRules[$id]) - $state")
    }

    if ($notBlocking.Count -gt 0) {
        $severity = if ($notBlocking.Count -ge 8) { 'High' } else { 'Medium' }
        Add-Finding -Category $script:DefenderCategory -Check 'AsrRules' -Severity $severity `
                    -Title "$($notBlocking.Count) of $($highValue.Count) high-value ASR rules are not in Block mode" `
                    -Detail 'Attack Surface Reduction rules block whole techniques rather than specific files, so they stop malware that has no signature. They are off by default on consumer Windows, which is why this is worth fixing even on a clean machine.' `
                    -Recommendation 'Enable with: Add-MpPreference -AttackSurfaceReductionRules_Ids <GUID> -AttackSurfaceReductionRules_Actions Enabled. Start in Audit mode (-Actions AuditMode) if you are worried about breaking an application.' `
                    -Evidence ([ordered]@{ 'Rules not blocking' = ($notBlocking -join ' | ') })
    }

    # A rule explicitly configured to Disabled (0) is different from unset.
    foreach ($id in $configured.Keys) {
        if ($configured[$id] -ne 0) { continue }
        if (-not $script:AsrRules.ContainsKey($id)) { continue }
        Add-Finding -Category $script:DefenderCategory -Check 'AsrRules' -Severity 'Medium' `
                    -Title "ASR rule explicitly disabled: $($script:AsrRules[$id])" `
                    -Detail 'This rule has been configured and then set to Disabled, which is a deliberate action rather than a default.' `
                    -Recommendation "Re-enable with Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled" `
                    -Evidence ([ordered]@{ 'Rule GUID' = $id; 'Action' = 'Disabled (0)' })
    }
}

function Test-DefenderPolicyOverrides {
    Write-ScanLog -Message 'Defender policy overrides in the registry' -Level 'Step'

    $policyChecks = @(
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'; Name = 'DisableAntiSpyware'; Label = 'Defender is disabled by policy'; Severity = 'Critical' }
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'; Name = 'DisableAntiVirus';   Label = 'Defender antivirus is disabled by policy'; Severity = 'Critical' }
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'DisableRealtimeMonitoring'; Label = 'Real-time monitoring is disabled by policy'; Severity = 'Critical' }
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'DisableBehaviorMonitoring'; Label = 'Behaviour monitoring is disabled by policy'; Severity = 'High' }
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'DisableScanOnRealtimeEnable'; Label = 'Real-time scan-on-enable is disabled by policy'; Severity = 'High' }
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'; Name = 'SpynetReporting'; Label = 'Cloud protection disabled by policy'; Severity = 'Medium'; ExpectZeroIsBad = $true }
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting'; Name = 'DisableEnhancedNotifications'; Label = 'Defender notifications suppressed by policy'; Severity = 'Medium' }
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Microsoft Antimalware'; Name = 'DisableAntiSpyware'; Label = 'Legacy antimalware policy disables Defender'; Severity = 'Critical' }
    )

    foreach ($check in $policyChecks) {
        $value = Get-RegistryValue -Path $check.Path -Name $check.Name
        if ($null -eq $value) { continue }

        $isBad = if ($check.ContainsKey('ExpectZeroIsBad') -and $check.ExpectZeroIsBad) { [int]$value -eq 0 } else { [int]$value -eq 1 }
        if (-not $isBad) { continue }

        Add-Finding -Category $script:DefenderCategory -Check 'DefenderPolicy' -Severity $check.Severity `
                    -Title $check.Label `
                    -Detail "A Group Policy registry value is forcing this setting off. On an unmanaged home PC nothing should be writing these keys, so their presence is itself suspicious - this is a common way to keep Defender down across reboots." `
                    -Recommendation "Delete the value $($check.Name) under $($check.Path), then reboot and confirm Defender comes back up." `
                    -Evidence ([ordered]@{ 'Key' = $check.Path; 'Value name' = $check.Name; 'Data' = $value })
    }

    # Windows Security Center notification suppression.
    $wscNotify = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications' -Name 'DisableNotifications'
    if ([int]$wscNotify -eq 1) {
        Add-Finding -Category $script:DefenderCategory -Check 'DefenderPolicy' -Severity 'Medium' `
                    -Title 'Windows Security notifications are suppressed' `
                    -Detail 'Alerts from Windows Security will not be shown, so a detection could happen without you ever seeing it.' `
                    -Recommendation 'Set DisableNotifications to 0 under HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications.' `
                    -Evidence ([ordered]@{ 'DisableNotifications' = $wscNotify })
    }
}

function Test-DefenderServiceHealth {
    Write-ScanLog -Message 'Security service health' -Level 'Step'

    $services = @(
        @{ Name = 'WinDefend';   Label = 'Microsoft Defender Antivirus Service'; Severity = 'Critical' }
        @{ Name = 'WdNisSvc';    Label = 'Defender Network Inspection Service';  Severity = 'Medium' }
        @{ Name = 'Sense';       Label = 'Defender for Endpoint sensor';         Severity = 'Low' }
        @{ Name = 'SecurityHealthService'; Label = 'Windows Security Health Service'; Severity = 'Medium' }
        @{ Name = 'wscsvc';      Label = 'Security Center Service';              Severity = 'Medium' }
        @{ Name = 'MpsSvc';      Label = 'Windows Defender Firewall Service';    Severity = 'High' }
        @{ Name = 'EventLog';    Label = 'Windows Event Log';                    Severity = 'High' }
        @{ Name = 'Schedule';    Label = 'Task Scheduler';                       Severity = 'Medium' }
    )

    foreach ($entry in $services) {
        $service = Get-Service -Name $entry.Name -ErrorAction SilentlyContinue
        if (-not $service) { continue }

        $startMode = $null
        try { $startMode = (Get-CimInstance Win32_Service -Filter "Name='$($entry.Name)'" -ErrorAction Stop).StartMode } catch { }

        if ($service.Status -ne 'Running') {
            Add-Finding -Category $script:DefenderCategory -Check 'ServiceHealth' -Severity $entry.Severity `
                        -Title "$($entry.Label) is not running" `
                        -Detail "Service '$($entry.Name)' is in state $($service.Status) with start mode $startMode." `
                        -Recommendation "Start it with Start-Service $($entry.Name). If it will not start or stops again, treat that as active interference." `
                        -Evidence ([ordered]@{ 'Service' = $entry.Name; 'Status' = "$($service.Status)"; 'Start mode' = $startMode })
        }
        elseif ($startMode -eq 'Disabled') {
            Add-Finding -Category $script:DefenderCategory -Check 'ServiceHealth' -Severity $entry.Severity `
                        -Title "$($entry.Label) is set to Disabled" `
                        -Detail 'The service is running now but will not start after the next reboot.' `
                        -Recommendation "Set-Service $($entry.Name) -StartupType Automatic" `
                        -Evidence ([ordered]@{ 'Service' = $entry.Name; 'Start mode' = 'Disabled' })
        }
    }

    # Anything else registered as the active AV product.
    try {
        $products = @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName 'AntiVirusProduct' -ErrorAction Stop)
        $thirdParty = @($products | Where-Object { $_.displayName -notmatch 'Windows Defender|Microsoft Defender' })
        if ($thirdParty.Count -gt 0) {
            Add-Finding -Category $script:DefenderCategory -Check 'ServiceHealth' -Severity 'Info' `
                        -Title "Third-party antivirus registered: $(($thirdParty | ForEach-Object { $_.displayName }) -join ', ')" `
                        -Detail 'When another AV registers itself, Defender steps down to passive mode. That is expected - but verify you actually installed these products.' `
                        -Recommendation 'Remove any AV product you do not recognise; rogue "security" software is a common malware disguise.' `
                        -Evidence ([ordered]@{ 'Products' = (($products | ForEach-Object { $_.displayName }) -join ', ') })
        }
    }
    catch { }
}

function Test-CredentialHardening {
    <#
        .SYNOPSIS
        Settings that decide how easy it is to steal credentials off this box.
        None of these produce an antivirus detection when changed.
    #>
    Write-ScanLog -Message 'Credential exposure settings' -Level 'Step'

    $wdigest = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential'
    if ([int]$wdigest -eq 1) {
        Add-Finding -Category $script:DefenderCategory -Check 'CredentialHardening' -Severity 'Critical' `
                    -Title 'WDigest is caching plaintext credentials in memory' `
                    -Detail 'UseLogonCredential = 1 forces Windows to keep your password in cleartext inside lsass.exe. This is off by default on modern Windows and is one of the first things an attacker enables after gaining admin, because it turns a memory dump into a plaintext password.' `
                    -Recommendation 'Set UseLogonCredential to 0 under HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest, reboot, and change your password from a known-clean device.' `
                    -Evidence ([ordered]@{ 'UseLogonCredential' = $wdigest })
    }

    $runAsPpl = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL'
    if ([int]$runAsPpl -ne 1) {
        Add-Finding -Category $script:DefenderCategory -Check 'CredentialHardening' -Severity 'Medium' `
                    -Title 'LSA Protection (RunAsPPL) is not enabled' `
                    -Detail 'LSA Protection runs lsass.exe as a protected process, which blocks most credential-dumping tools from reading its memory even with administrator rights.' `
                    -Recommendation 'Set RunAsPPL to 1 (DWORD) under HKLM\SYSTEM\CurrentControlSet\Control\Lsa and reboot. Check for driver compatibility first if you use smartcard or third-party auth software.' `
                    -Evidence ([ordered]@{ 'RunAsPPL' = if ($null -eq $runAsPpl) { 'not set' } else { $runAsPpl } })
    }

    $restrictAnonymous = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous'
    if ($null -ne $restrictAnonymous -and [int]$restrictAnonymous -eq 0) {
        Add-Finding -Category $script:DefenderCategory -Check 'CredentialHardening' -Severity 'Low' `
                    -Title 'Anonymous enumeration of accounts and shares is permitted' `
                    -Detail 'RestrictAnonymous = 0 lets an unauthenticated network peer list local accounts and shares.' `
                    -Recommendation 'Set RestrictAnonymous to 1 and RestrictAnonymousSAM to 1 under HKLM\SYSTEM\CurrentControlSet\Control\Lsa.' `
                    -Evidence ([ordered]@{ 'RestrictAnonymous' = $restrictAnonymous })
    }

    # Cleartext autologon password.
    $autoLogon = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultPassword'
    if ($autoLogon) {
        Add-Finding -Category $script:DefenderCategory -Check 'CredentialHardening' -Severity 'High' `
                    -Title 'A logon password is stored in cleartext in the registry' `
                    -Detail 'Winlogon\DefaultPassword holds an account password in plain text, readable by any process running as that user. This is set up by the autologon feature.' `
                    -Recommendation 'Remove the DefaultPassword value. If you need autologon, use Sysinternals Autologon, which stores the secret in the LSA instead.' `
                    -Evidence ([ordered]@{
                        'DefaultUserName' = (Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultUserName')
                        'AutoAdminLogon'  = (Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon')
                        'Password stored' = 'yes (value not printed)'
                    })
    }
}

function Test-SystemHardening {
    Write-ScanLog -Message 'System hardening posture' -Level 'Step'

    # --- UAC -------------------------------------------------------------
    $systemPolicy = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $enableLua    = Get-RegistryValue -Path $systemPolicy -Name 'EnableLUA'
    $consent      = Get-RegistryValue -Path $systemPolicy -Name 'ConsentPromptBehaviorAdmin'
    $secureDesk   = Get-RegistryValue -Path $systemPolicy -Name 'PromptOnSecureDesktop'
    $tokenFilter  = Get-RegistryValue -Path $systemPolicy -Name 'LocalAccountTokenFilterPolicy'

    if ($null -ne $enableLua -and [int]$enableLua -eq 0) {
        Add-Finding -Category $script:DefenderCategory -Check 'Hardening' -Severity 'Critical' `
                    -Title 'User Account Control is completely disabled' `
                    -Detail 'EnableLUA = 0 means every process started by an administrator runs fully elevated with no prompt. It also disables the sandboxing that protects Edge and other applications.' `
                    -Recommendation 'Set EnableLUA to 1 and reboot.' `
                    -Evidence ([ordered]@{ 'EnableLUA' = $enableLua })
    }
    elseif ($null -ne $consent -and [int]$consent -eq 0) {
        Add-Finding -Category $script:DefenderCategory -Check 'Hardening' -Severity 'High' `
                    -Title 'UAC elevates administrators without prompting' `
                    -Detail 'ConsentPromptBehaviorAdmin = 0 ("Elevate without prompting") lets any process silently gain full administrator rights.' `
                    -Recommendation 'Set ConsentPromptBehaviorAdmin to 2 (always prompt on the secure desktop).' `
                    -Evidence ([ordered]@{ 'ConsentPromptBehaviorAdmin' = $consent })
    }
    elseif ($null -ne $consent -and [int]$consent -eq 5 -and $null -ne $secureDesk -and [int]$secureDesk -eq 0) {
        Add-Finding -Category $script:DefenderCategory -Check 'Hardening' -Severity 'Medium' `
                    -Title 'UAC prompts are not shown on the secure desktop' `
                    -Detail 'With PromptOnSecureDesktop = 0 the consent dialog can be manipulated by other software running in your session.' `
                    -Recommendation 'Set PromptOnSecureDesktop to 1.' `
                    -Evidence ([ordered]@{ 'PromptOnSecureDesktop' = $secureDesk; 'ConsentPromptBehaviorAdmin' = $consent })
    }

    if ([int]$tokenFilter -eq 1) {
        Add-Finding -Category $script:DefenderCategory -Check 'Hardening' -Severity 'High' `
                    -Title 'Remote UAC filtering is disabled (LocalAccountTokenFilterPolicy)' `
                    -Detail 'This lets local accounts connect over the network with a full administrator token. It is a requirement for most remote lateral-movement techniques and is not a Windows default.' `
                    -Recommendation 'Delete LocalAccountTokenFilterPolicy, or set it to 0, under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System.' `
                    -Evidence ([ordered]@{ 'LocalAccountTokenFilterPolicy' = $tokenFilter })
    }

    # --- SMBv1 -----------------------------------------------------------
    $smb1 = $null
    try { $smb1 = Get-SmbServerConfiguration -ErrorAction Stop } catch { }
    if ($smb1 -and $smb1.PSObject.Properties['EnableSMB1Protocol'] -and $smb1.EnableSMB1Protocol) {
        Add-Finding -Category $script:DefenderCategory -Check 'Hardening' -Severity 'High' `
                    -Title 'SMBv1 is enabled' `
                    -Detail 'SMBv1 is the protocol exploited by EternalBlue/WannaCry. It has no message signing worth the name and is deprecated; Windows has not needed it since Windows 7 era devices.' `
                    -Recommendation 'Disable with: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol' `
                    -Evidence ([ordered]@{ 'EnableSMB1Protocol' = 'True' })
    }
    if ($smb1 -and $smb1.PSObject.Properties['RequireSecuritySignature'] -and -not $smb1.RequireSecuritySignature) {
        Add-Finding -Category $script:DefenderCategory -Check 'Hardening' -Severity 'Low' `
                    -Title 'SMB signing is not required' `
                    -Detail 'Without required signing, SMB sessions can be relayed by an attacker on the same network.' `
                    -Recommendation 'Set-SmbServerConfiguration -RequireSecuritySignature $true' `
                    -Evidence ([ordered]@{ 'RequireSecuritySignature' = 'False' })
    }

    # --- RDP -------------------------------------------------------------
    $denyRdp = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections'
    if ($null -ne $denyRdp -and [int]$denyRdp -eq 0) {
        $nla  = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication'
        $port = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'PortNumber'

        $severity = if ([int]$nla -ne 1) { 'High' } else { 'Medium' }
        $detail = 'Remote Desktop accepts incoming connections on this machine. '
        if ([int]$nla -ne 1) { $detail += 'Network Level Authentication is OFF, so an attacker reaches the logon screen - and the pre-auth attack surface - without any credentials. ' }
        $detail += 'RDP brute-forcing is one of the most common ways home and small-business machines are taken over.'

        Add-Finding -Category $script:DefenderCategory -Check 'Hardening' -Severity $severity `
                    -Title 'Remote Desktop is enabled' `
                    -Detail $detail `
                    -Recommendation 'If you do not use RDP, turn it off in Settings > System > Remote Desktop. If you do, require Network Level Authentication, never expose port 3389 to the internet, and put it behind a VPN.' `
                    -Evidence ([ordered]@{
                        'fDenyTSConnections'   = $denyRdp
                        'NLA (UserAuthentication)' = if ($null -eq $nla) { 'not set' } else { $nla }
                        'Listening port'       = if ($null -eq $port) { '3389 (default)' } else { $port }
                    })
    }

    # --- Firewall --------------------------------------------------------
    try {
        foreach ($firewallProfile in (Get-NetFirewallProfile -ErrorAction Stop)) {
            if (-not $firewallProfile.Enabled) {
                Add-Finding -Category $script:DefenderCategory -Check 'Hardening' -Severity 'High' `
                            -Title "Firewall is off for the $($firewallProfile.Name) profile" `
                            -Detail 'With the firewall disabled, every listening service on this machine is reachable from the network it is attached to.' `
                            -Recommendation "Set-NetFirewallProfile -Profile $($firewallProfile.Name) -Enabled True" `
                            -Evidence ([ordered]@{ 'Profile' = $firewallProfile.Name; 'Enabled' = 'False' })
            }
            elseif ("$($firewallProfile.DefaultInboundAction)" -eq 'Allow') {
                Add-Finding -Category $script:DefenderCategory -Check 'Hardening' -Severity 'High' `
                            -Title "Firewall default inbound action is Allow ($($firewallProfile.Name) profile)" `
                            -Detail 'The firewall is enabled but permits unsolicited inbound traffic by default, which negates most of its value.' `
                            -Recommendation "Set-NetFirewallProfile -Profile $($firewallProfile.Name) -DefaultInboundAction Block" `
                            -Evidence ([ordered]@{ 'Profile' = $firewallProfile.Name; 'DefaultInboundAction' = 'Allow' })
            }
        }
    }
    catch { }

    # --- Boot integrity --------------------------------------------------
    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
        if (-not $secureBoot) {
            Add-Finding -Category $script:DefenderCategory -Check 'Hardening' -Severity 'Medium' `
                        -Title 'Secure Boot is disabled' `
                        -Detail 'Secure Boot prevents unsigned bootloaders and boot-level rootkits from loading before Windows. It is also a prerequisite for several other protections.' `
                        -Recommendation 'Enable Secure Boot in UEFI firmware settings.' `
                        -Evidence ([ordered]@{ 'Secure Boot' = 'Disabled' })
        }
    }
    catch { }

    # --- BitLocker -------------------------------------------------------
    try {
        $systemVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        if ("$($systemVolume.ProtectionStatus)" -ne 'On') {
            Add-Finding -Category $script:DefenderCategory -Check 'Hardening' -Severity 'Medium' `
                        -Title "BitLocker is not protecting $env:SystemDrive" `
                        -Detail 'Without full-disk encryption, anyone with physical access can read every file and extract credential material by booting from USB - no password needed.' `
                        -Recommendation 'Enable BitLocker (or Device Encryption on Home editions) and store the recovery key somewhere off this machine.' `
                        -Evidence ([ordered]@{
                            'Mount point'       = $systemVolume.MountPoint
                            'Protection status' = "$($systemVolume.ProtectionStatus)"
                            'Encryption'        = "$($systemVolume.VolumeStatus)"
                        })
        }
    }
    catch { }

    # --- Script visibility ----------------------------------------------
    $scriptBlockLogging = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging'
    if ([int]$scriptBlockLogging -ne 1) {
        Add-Finding -Category $script:DefenderCategory -Check 'Hardening' -Severity 'Low' `
                    -Title 'PowerShell script block logging is off' `
                    -Detail 'Script block logging records the actual code PowerShell executes, after de-obfuscation. Without it, an encoded malicious command leaves almost no forensic trace.' `
                    -Recommendation 'Create HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging and set EnableScriptBlockLogging = 1 (DWORD). Events land in Microsoft-Windows-PowerShell/Operational, ID 4104.' `
                    -Evidence ([ordered]@{ 'EnableScriptBlockLogging' = if ($null -eq $scriptBlockLogging) { 'not set' } else { $scriptBlockLogging } })
    }

    # PowerShell v2 bypasses v5's logging and AMSI entirely.
    try {
        $v2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction Stop
        if ($v2 -and "$($v2.State)" -eq 'Enabled') {
            Add-Finding -Category $script:DefenderCategory -Check 'Hardening' -Severity 'Medium' `
                        -Title 'PowerShell v2 engine is installed' `
                        -Detail 'The v2 engine predates AMSI and script block logging. Running powershell.exe -Version 2 downgrades into it and silently bypasses both Defender script scanning and all logging.' `
                        -Recommendation 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root' `
                        -Evidence ([ordered]@{ 'Feature state' = "$($v2.State)" })
        }
    }
    catch { }

    # --- Installer privilege escalation ----------------------------------
    $alwaysElevatedMachine = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated'
    $alwaysElevatedUser    = Get-RegistryValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated'
    if ([int]$alwaysElevatedMachine -eq 1 -and [int]$alwaysElevatedUser -eq 1) {
        Add-Finding -Category $script:DefenderCategory -Check 'Hardening' -Severity 'Critical' `
                    -Title 'AlwaysInstallElevated is enabled for both machine and user' `
                    -Detail 'Any user on this machine can install an MSI package that runs as SYSTEM. This is a one-command privilege escalation to full system control and requires no exploit.' `
                    -Recommendation 'Set AlwaysInstallElevated to 0 in both HKLM and HKCU under SOFTWARE\Policies\Microsoft\Windows\Installer.' `
                    -Evidence ([ordered]@{ 'HKLM value' = $alwaysElevatedMachine; 'HKCU value' = $alwaysElevatedUser })
    }

    # --- Removable media autorun -----------------------------------------
    $noDriveTypeAutoRun = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun'
    if ($null -eq $noDriveTypeAutoRun -or ([int]$noDriveTypeAutoRun -band 0xFF) -ne 0xFF) {
        Add-Finding -Category $script:DefenderCategory -Check 'Hardening' -Severity 'Low' `
                    -Title 'AutoRun is not fully disabled for all drive types' `
                    -Detail 'AutoRun/AutoPlay on removable media is a long-standing infection route for USB-borne malware.' `
                    -Recommendation 'Set NoDriveTypeAutoRun to 255 (0xFF) under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer.' `
                    -Evidence ([ordered]@{ 'NoDriveTypeAutoRun' = if ($null -eq $noDriveTypeAutoRun) { 'not set' } else { $noDriveTypeAutoRun } })
    }
}

function Test-PatchLevel {
    Write-ScanLog -Message 'Patch level' -Level 'Step'

    # Get-HotFix only reflects the classic QFE mechanism and routinely misses
    # the cumulative updates that carry most of the actual security fixes on
    # Windows 10/11, which can make a fully patched machine look stale. Cross
    # -check against Windows Update's own last-success timestamp and trust
    # whichever source is more recent.
    $candidates = New-Object System.Collections.ArrayList

    try {
        $latestHotfix = Get-HotFix -ErrorAction Stop |
                        Where-Object { $_.InstalledOn } |
                        Sort-Object InstalledOn -Descending |
                        Select-Object -First 1
        if ($latestHotfix) {
            $null = $candidates.Add([pscustomobject]@{ Date = $latestHotfix.InstalledOn; Source = "Hotfix $($latestHotfix.HotFixID)" })
        }
    }
    catch { }

    $lastSuccess = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install' -Name 'LastSuccessTime'
    if ($lastSuccess) {
        $parsed = [datetime]::MinValue
        if ([datetime]::TryParse("$lastSuccess", [ref]$parsed)) {
            $null = $candidates.Add([pscustomobject]@{ Date = $parsed; Source = 'Windows Update history' })
        }
    }

    if ($candidates.Count -gt 0) {
        $latest = $candidates | Sort-Object Date -Descending | Select-Object -First 1
        $age = ((Get-Date) - $latest.Date).TotalDays
        if ($age -gt 60) {
            $severity = if ($age -gt 120) { 'High' } else { 'Medium' }
            Add-Finding -Category $script:DefenderCategory -Check 'PatchLevel' -Severity $severity `
                        -Title "No Windows update installed in $([int]$age) days" `
                        -Detail 'Unpatched machines are exploited through vulnerabilities that no antivirus product will catch, because the exploit runs inside a trusted process.' `
                        -Recommendation 'Run Windows Update. If updates are failing or the service is disabled, resolve that first - blocked updates are a common post-compromise action.' `
                        -Evidence ([ordered]@{
                            'Most recent update' = $latest.Date
                            'Source'             = $latest.Source
                            'Days ago'           = [int]$age
                        })
        }
    }

    $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    if ($wuService) {
        $startMode = $null
        try { $startMode = (Get-CimInstance Win32_Service -Filter "Name='wuauserv'" -ErrorAction Stop).StartMode } catch { }
        if ($startMode -eq 'Disabled') {
            Add-Finding -Category $script:DefenderCategory -Check 'PatchLevel' -Severity 'High' `
                        -Title 'Windows Update service is disabled' `
                        -Detail 'The machine will not receive security patches or Defender platform updates.' `
                        -Recommendation 'Set-Service wuauserv -StartupType Manual and check for updates.' `
                        -Evidence ([ordered]@{ 'Start mode' = 'Disabled'; 'Status' = "$($wuService.Status)" })
        }
    }
}

function Invoke-DefenderChecks {
    Invoke-Check -Name 'DefenderStatus'      -Body { Test-DefenderStatus }
    Invoke-Check -Name 'DefenderExclusions'  -Body { Test-DefenderExclusions }
    Invoke-Check -Name 'AsrRules'            -Body { Test-AsrRules }
    Invoke-Check -Name 'DefenderPolicy'      -Body { Test-DefenderPolicyOverrides }
    Invoke-Check -Name 'ServiceHealth'       -Body { Test-DefenderServiceHealth }
    Invoke-Check -Name 'CredentialHardening' -Body { Test-CredentialHardening }
    Invoke-Check -Name 'SystemHardening'     -Body { Test-SystemHardening }
    Invoke-Check -Name 'PatchLevel'          -Body { Test-PatchLevel }
}
