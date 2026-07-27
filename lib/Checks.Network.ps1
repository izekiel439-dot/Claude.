<#
    Checks.Network.ps1 - Network exposure and trust-store integrity.

    Two themes here. First, what on this machine is reachable or talking out,
    attributed to the binary responsible. Second, the plumbing that decides
    where traffic goes and who it trusts - hosts file, DNS, proxy/PAC and the
    root certificate store. A rogue root CA is completely invisible to
    Defender and silently defeats HTTPS for every application on the box.
#>

$script:NetworkCategory = 'Network & Trust'

function Test-ListeningPorts {
    Write-ScanLog -Message 'Listening ports' -Level 'Step'

    $listeners = $null
    try { $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop) } catch { }
    if (-not $listeners) { return }

    # Ports Windows itself always has open; not interesting on their own.
    $expectedSystemPorts = @(135, 445, 139, 5985, 5986, 49664, 49665, 49666, 49667, 49668, 49669, 49670)

    foreach ($listener in $listeners) {
        $process   = Get-ProcessForPid -ProcessId $listener.OwningProcess
        $imagePath = if ($process) { $process.Path } else { $null }
        $signature = Get-SignatureInfo -Path $imagePath

        $isWildcard = ("$($listener.LocalAddress)" -eq '0.0.0.0' -or "$($listener.LocalAddress)" -eq '::')
        $isLoopback = ("$($listener.LocalAddress)" -eq '127.0.0.1' -or "$($listener.LocalAddress)" -eq '::1')

        $reasons    = New-Object System.Collections.ArrayList
        $severities = New-Object System.Collections.ArrayList

        foreach ($reason in (Test-SuspiciousPath -Path $imagePath)) {
            $null = $reasons.Add($reason)
            $null = $severities.Add('High')
        }

        if ($imagePath -and $signature.Exists -and -not $signature.IsMicrosoft) {
            if (-not $signature.IsSigned) {
                $null = $reasons.Add('The listening process is not digitally signed')
                $null = $severities.Add(($(if ($isWildcard) { 'High' } else { 'Medium' })))
            }
            elseif (-not $signature.IsTrusted) {
                $null = $reasons.Add("The listening process has an invalid signature ($($signature.Status))")
                $null = $severities.Add('High')
            }
        }

        if (-not $imagePath -and $listener.OwningProcess -gt 4) {
            $null = $reasons.Add('The owning process image could not be read, which can indicate a protected or hidden process')
            $null = $severities.Add('Medium')
        }

        # A wildcard bind on a high port by a non-Microsoft binary is the
        # classic shape of a backdoor or an unintentionally exposed service.
        if ($isWildcard -and -not $signature.IsMicrosoft -and $expectedSystemPorts -notcontains [int]$listener.LocalPort) {
            $null = $reasons.Add("Accepts connections from any network interface on port $($listener.LocalPort)")
            $null = $severities.Add('Medium')
        }

        if ($isLoopback -and $reasons.Count -eq 0) { continue }
        if ($reasons.Count -eq 0) { continue }

        $severity = Get-WorstSeverity -Severities @($severities) -Default 'Low'

        Add-Finding -Category $script:NetworkCategory -Check 'ListeningPorts' -Severity $severity `
                    -Title "Port $($listener.LocalPort) is open, held by $(if ($process) { $process.Name } else { "PID $($listener.OwningProcess)" })" `
                    -Detail ($reasons -join '; ') `
                    -Recommendation 'Confirm the program should be accepting connections. If you do not recognise it, stop the process, block the port in Windows Firewall, and investigate the binary.' `
                    -Evidence ([ordered]@{
                        'Local endpoint' = "$($listener.LocalAddress):$($listener.LocalPort)"
                        'Process'        = if ($process) { "$($process.Name) (PID $($process.Id))" } else { "PID $($listener.OwningProcess)" }
                        'Image'          = $imagePath
                        'Signature'      = if ($signature.Exists) { "$($signature.Status) $($signature.Signer)" } else { 'unknown' }
                        'Publisher'      = $signature.Company
                    })
    }
}

function Test-OutboundConnections {
    Write-ScanLog -Message 'Established outbound connections' -Level 'Step'

    $connections = $null
    try { $connections = @(Get-NetTCPConnection -State Established -ErrorAction Stop) } catch { }
    if (-not $connections) { return }

    $reported = @{}

    foreach ($connection in $connections) {
        $remote = "$($connection.RemoteAddress)"
        if ($remote -match '^(127\.|::1$|0\.0\.0\.0)') { continue }
        # Private ranges: normal LAN chatter, not egress.
        if ($remote -match '^(10\.|192\.168\.|169\.254\.|fe80:)') { continue }
        if ($remote -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { continue }

        $process   = Get-ProcessForPid -ProcessId $connection.OwningProcess
        $imagePath = if ($process) { $process.Path } else { $null }
        if (-not $imagePath) { continue }

        $signature = Get-SignatureInfo -Path $imagePath
        if ($signature.IsMicrosoft) { continue }

        $reasons = @(Test-SuspiciousPath -Path $imagePath)
        if (-not $signature.IsSigned)       { $reasons += 'The connecting process is unsigned' }
        elseif (-not $signature.IsTrusted)  { $reasons += "The connecting process has an invalid signature ($($signature.Status))" }
        if ($reasons.Count -eq 0) { continue }

        # One finding per binary, not per socket.
        $key = $imagePath.ToLowerInvariant()
        if ($reported.ContainsKey($key)) { continue }
        $reported[$key] = $true

        $peers = @($connections |
                   Where-Object { $_.OwningProcess -eq $connection.OwningProcess } |
                   ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort)" } |
                   Select-Object -Unique -First 12)

        Add-Finding -Category $script:NetworkCategory -Check 'OutboundConnections' -Severity 'High' `
                    -Title "Unsigned process '$($process.Name)' has active internet connections" `
                    -Detail (($reasons -join '; ') + '. An unsigned binary holding open outbound sessions is the normal shape of command-and-control or data exfiltration traffic.') `
                    -Recommendation 'Identify the program. If you cannot attribute it to software you installed, kill the process, block it in the firewall, and submit the file to VirusTotal before deleting.' `
                    -Evidence ([ordered]@{
                        'Process'    = "$($process.Name) (PID $($process.Id))"
                        'Image'      = $imagePath
                        'Signature'  = "$($signature.Status) $($signature.Signer)"
                        'Publisher'  = $signature.Company
                        'Remote endpoints' = ($peers -join ', ')
                    })
    }
}

function Test-HostsFile {
    Write-ScanLog -Message 'Hosts file' -Level 'Step'

    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (-not (Test-Path -LiteralPath $hostsPath)) { return }

    $lines = @()
    try { $lines = @(Get-Content -LiteralPath $hostsPath -ErrorAction Stop) } catch { return }

    # Domains whose blackholing is a strong signal of tampering: it keeps the
    # machine from updating or from reporting a detection.
    $securityDomains = 'microsoft\.com|windowsupdate|defender|msftncsi|msftconnecttest|sophos|mcafee|symantec|norton|kaspersky|avast|avg\.|bitdefender|eset|trendmicro|malwarebytes|virustotal|clamav|f-secure|comodo|sucuri|threatfire'

    $entries = New-Object System.Collections.ArrayList
    $lineNumber = 0
    foreach ($line in $lines) {
        $lineNumber++
        $trimmed = "$line".Trim()
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith('#')) { continue }

        $parts = $trimmed -split '\s+'
        if ($parts.Count -lt 2) { continue }

        $address   = $parts[0]
        $hostnames = @($parts[1..($parts.Count - 1)] | Where-Object { $_ -and -not $_.StartsWith('#') })
        if ($hostnames.Count -eq 0) { continue }

        # The stock file's own localhost entries.
        if ($hostnames.Count -eq 1 -and $hostnames[0] -match '^(localhost|::1)$') { continue }

        $null = $entries.Add([pscustomobject]@{ Line = $lineNumber; Address = $address; Hosts = $hostnames })
    }

    if ($entries.Count -eq 0) { return }

    $securityHits = @($entries | Where-Object { ($_.Hosts -join ' ') -match $securityDomains })
    if ($securityHits.Count -gt 0) {
        Add-Finding -Category $script:NetworkCategory -Check 'HostsFile' -Severity 'Critical' `
                    -Title 'Hosts file blackholes security or update domains' `
                    -Detail 'Entries in the hosts file redirect antivirus, telemetry or Windows Update hostnames. This is a deliberate step to stop the machine from receiving definition updates or reporting a detection, and it is one of the clearest indicators of an active infection.' `
                    -Recommendation "Open $hostsPath as administrator and remove these entries, then run Update-MpSignature and check for Windows updates." `
                    -Evidence ([ordered]@{
                        'Entries' = (($securityHits | ForEach-Object { "line $($_.Line): $($_.Address) $($_.Hosts -join ' ')" }) -join ' | ')
                        'File'    = $hostsPath
                    })
    }

    $redirects = @($entries | Where-Object {
        $_.Address -notmatch '^(0\.0\.0\.0|127\.0\.0\.1|::1)$' -and ($_.Hosts -join ' ') -notmatch $securityDomains
    })
    if ($redirects.Count -gt 0) {
        Add-Finding -Category $script:NetworkCategory -Check 'HostsFile' -Severity 'High' `
                    -Title "Hosts file redirects $($redirects.Count) hostname(s) to a specific address" `
                    -Detail 'These entries send traffic for a real hostname to an address of someone else''s choosing, bypassing DNS entirely. Legitimate uses exist (development, ad blocking), but this is also how a phishing page is made to appear at a bank''s address.' `
                    -Recommendation "Review each entry in $hostsPath and remove anything you did not add." `
                    -Evidence ([ordered]@{
                        'Entries' = (($redirects | Select-Object -First 25 | ForEach-Object { "line $($_.Line): $($_.Address) -> $($_.Hosts -join ' ')" }) -join ' | ')
                    })
    }

    $blocked = @($entries | Where-Object { $_.Address -match '^(0\.0\.0\.0|127\.0\.0\.1)$' -and ($_.Hosts -join ' ') -notmatch $securityDomains })
    if ($blocked.Count -gt 50) {
        Add-Finding -Category $script:NetworkCategory -Check 'HostsFile' -Severity 'Info' `
                    -Title "Hosts file blocks $($blocked.Count) hostnames" `
                    -Detail 'A large blocklist is typical of an ad-blocking hosts file. Noted for completeness rather than as a problem.' `
                    -Recommendation 'No action needed if you installed a hosts-based ad blocker.' `
                    -Evidence ([ordered]@{ 'Blocked entries' = $blocked.Count; 'Sample' = (($blocked | Select-Object -First 5 | ForEach-Object { $_.Hosts -join ' ' }) -join ', ') })
    }
}

function Test-DnsConfiguration {
    Write-ScanLog -Message 'DNS configuration' -Level 'Step'

    # Well-known resolvers, so a deliberate choice is not reported as a hijack.
    $knownResolvers = @(
        '8.8.8.8','8.8.4.4','1.1.1.1','1.0.0.1','9.9.9.9','149.112.112.112',
        '208.67.222.222','208.67.220.220','76.76.2.0','76.76.10.0','94.140.14.14','94.140.15.15',
        '2001:4860:4860::8888','2001:4860:4860::8844','2606:4700:4700::1111','2620:fe::fe'
    )

    try {
        $adapters = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
                      Where-Object { $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0 })

        foreach ($adapter in $adapters) {
            $state = $null
            try { $state = Get-NetAdapter -InterfaceIndex $adapter.InterfaceIndex -ErrorAction Stop } catch { }
            if ($state -and "$($state.Status)" -ne 'Up') { continue }

            foreach ($server in $adapter.ServerAddresses) {
                if ($knownResolvers -contains $server) { continue }
                # Router-assigned resolvers on the local network are normal.
                if ($server -match '^(10\.|192\.168\.|127\.)') { continue }
                if ($server -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { continue }

                Add-Finding -Category $script:NetworkCategory -Check 'DnsConfiguration' -Severity 'High' `
                            -Title "Unrecognised public DNS server configured: $server" `
                            -Detail "Adapter '$($adapter.InterfaceAlias)' resolves names using a public address that is neither your local router nor a well-known resolver. Whoever runs that server decides where every hostname on this machine points - including your bank and your update servers." `
                            -Recommendation 'Unless you deliberately configured this resolver, reset the adapter to obtain DNS automatically (Settings > Network > adapter > Edit DNS > Automatic).' `
                            -Evidence ([ordered]@{
                                'Adapter'     = $adapter.InterfaceAlias
                                'DNS servers' = ($adapter.ServerAddresses -join ', ')
                            })
            }
        }
    }
    catch { }

    # DNS over the NRPT / policy path can silently override adapter settings.
    try {
        $nrpt = @(Get-DnsClientNrptRule -ErrorAction Stop)
        foreach ($rule in $nrpt) {
            if (-not $rule.NameServers) { continue }
            Add-Finding -Category $script:NetworkCategory -Check 'DnsConfiguration' -Severity 'Medium' `
                        -Title "DNS policy rule redirects '$($rule.Namespace)'" `
                        -Detail 'A Name Resolution Policy Table rule overrides normal DNS for this namespace. Common in corporate/VPN setups, unusual on a personal machine.' `
                        -Recommendation 'If this machine is not managed by an employer and you do not run a VPN that installs DNS policy, remove the rule with Remove-DnsClientNrptRule.' `
                        -Evidence ([ordered]@{
                            'Namespace'   = ($rule.Namespace -join ', ')
                            'Name servers'= ($rule.NameServers -join ', ')
                        })
        }
    }
    catch { }
}

function Test-ProxyConfiguration {
    <#
        .SYNOPSIS
        Proxy and PAC settings.

        AutoConfigURL is the standout: it points at a remotely-hosted script
        that decides the route for every request, it is writable per-user
        without admin rights, and Defender has no opinion about it whatsoever.
    #>
    Write-ScanLog -Message 'Proxy and PAC configuration' -Level 'Step'

    foreach ($hive in (Get-UserHivePaths)) {
        $settingsKey = Join-Path $hive.Root 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
        if (-not (Test-Path -LiteralPath $settingsKey)) { continue }

        $autoConfigUrl = Get-RegistryValue -Path $settingsKey -Name 'AutoConfigURL'
        if (-not [string]::IsNullOrWhiteSpace("$autoConfigUrl")) {
            Add-Finding -Category $script:NetworkCategory -Check 'ProxyConfiguration' -Severity 'Critical' `
                        -Title "Automatic proxy configuration script is set for $($hive.User)" `
                        -Detail "Every HTTP and HTTPS request from this user is routed according to a script fetched from '$autoConfigUrl'. Whoever controls that URL controls where your traffic goes, can selectively route banking or webmail through their own server, and can change the rules at any time without touching this machine again." `
                        -Recommendation "Unless your workplace configured this, clear it: Remove-ItemProperty -Path '$settingsKey' -Name AutoConfigURL, then restart your browsers." `
                        -Evidence ([ordered]@{ 'User' = $hive.User; 'AutoConfigURL' = "$autoConfigUrl"; 'Key' = $settingsKey })
        }

        $proxyEnable = Get-RegistryValue -Path $settingsKey -Name 'ProxyEnable'
        $proxyServer = Get-RegistryValue -Path $settingsKey -Name 'ProxyServer'
        if ([int]$proxyEnable -eq 1 -and -not [string]::IsNullOrWhiteSpace("$proxyServer")) {
            $severity = if ("$proxyServer" -match '^(127\.0\.0\.1|localhost)') { 'Medium' } else { 'High' }
            $detail = "Traffic for $($hive.User) is routed through '$proxyServer'. "
            $detail += if ($severity -eq 'Medium') {
                'The proxy is local, which is typical of a debugging tool, a VPN client or a content filter - but also of an interception implant.'
            } else {
                'A remote proxy sees, and can modify, every unencrypted request. Combined with an installed root certificate it can read HTTPS too.'
            }

            Add-Finding -Category $script:NetworkCategory -Check 'ProxyConfiguration' -Severity $severity `
                        -Title "HTTP proxy is configured for $($hive.User)" `
                        -Detail $detail `
                        -Recommendation 'Check Settings > Network & Internet > Proxy. If you did not set this up, turn it off and cross-reference the root certificate findings in this report.' `
                        -Evidence ([ordered]@{
                            'User'        = $hive.User
                            'ProxyServer' = "$proxyServer"
                            'ProxyOverride' = (Get-RegistryValue -Path $settingsKey -Name 'ProxyOverride')
                        })
        }
    }

    # WinHTTP has its own proxy, used by services and by Windows Update.
    try {
        $winHttp = & netsh winhttp show proxy 2>$null | Out-String
        if ($winHttp -match 'Proxy Server\(s\)\s*:\s*(?<proxy>\S+)') {
            Add-Finding -Category $script:NetworkCategory -Check 'ProxyConfiguration' -Severity 'High' `
                        -Title "A system-wide WinHTTP proxy is set: $($Matches['proxy'])" `
                        -Detail 'WinHTTP is used by Windows services rather than by browsers - including Windows Update and Defender cloud lookups. A proxy here can quietly break or intercept those.' `
                        -Recommendation 'Clear it with: netsh winhttp reset proxy' `
                        -Evidence ([ordered]@{ 'netsh output' = ConvertTo-DisplayString $winHttp 400 })
        }
    }
    catch { }
}

function Test-RootCertificates {
    <#
        .SYNOPSIS
        Non-Microsoft roots in the trusted store.

        A certificate here can sign a TLS certificate for any website and every
        browser will accept it silently. Installing one is not malware and
        triggers no AV detection, which is exactly why interception tooling
        does it.
    #>
    Write-ScanLog -Message 'Trusted root certificate store' -Level 'Step'

    # Roots that ship with Windows or are added by common, legitimate software.
    $expectedIssuers = @(
        'Microsoft', 'DigiCert', 'VeriSign', 'GlobalSign', 'Baltimore', 'Thawte',
        'GeoTrust', 'Go Daddy', 'Entrust', 'COMODO', 'Sectigo', 'USERTrust',
        'AddTrust', 'Certum', 'QuoVadis', 'SecureTrust', 'Starfield', 'Symantec',
        'ISRG Root', "Let's Encrypt", 'Amazon Root', 'Google Trust Services', 'GTS Root',
        'Actalis', 'Buypass', 'D-TRUST', 'E-Tugra', 'HARICA', 'Hongkong Post',
        'IdenTrust', 'Network Solutions', 'SSL.com', 'SwissSign', 'T-TeleSec',
        'TWCA', 'TeliaSonera', 'Trustwave', 'UCA ', 'XRamp', 'Cybertrust',
        'AAA Certificate Services', 'Certigna', 'Chambers of Commerce', 'DST Root',
        'GDCA', 'GlobalTrust', 'ANF ', 'AC RAIZ', 'Autoridad', 'CFCA', 'OISTE',
        'SZAFIR', 'Security Communication', 'Staat der Nederlanden', 'TrustCor',
        'emSign', 'vTrus', 'Atos', 'Certainly', 'SecureSign', 'NAVER', 'Telia'
    )

    $stores = @(
        @{ Location = 'LocalMachine'; Name = 'Root';     Label = 'machine trusted roots';   BaseSeverity = 'High' }
        @{ Location = 'CurrentUser';  Name = 'Root';     Label = 'user trusted roots';      BaseSeverity = 'Critical' }
        @{ Location = 'LocalMachine'; Name = 'CA';       Label = 'machine intermediate CAs'; BaseSeverity = 'Medium' }
    )

    foreach ($storeSpec in $stores) {
        $certificates = @()
        try {
            $certificates = @(Get-ChildItem -Path "Cert:\$($storeSpec.Location)\$($storeSpec.Name)" -ErrorAction Stop)
        }
        catch { continue }

        foreach ($certificate in $certificates) {
            $subject = "$($certificate.Subject)"
            $issuer  = "$($certificate.Issuer)"

            $recognised = $false
            foreach ($known in $expectedIssuers) {
                if ($subject -like "*$known*") { $recognised = $true; break }
            }
            if ($recognised) { continue }

            $reasons    = New-Object System.Collections.ArrayList
            $severity   = $storeSpec.BaseSeverity
            $selfSigned = ($subject -eq $issuer)

            if ($selfSigned) { $null = $reasons.Add('The certificate is self-signed, so nobody vouched for it but itself') }

            # Interception proxies name themselves; this catches the honest ones.
            if ($subject -match 'Fiddler|Charles|Burp|mitmproxy|BrowserStack|Zscaler|Netskope|Forcepoint|Blue ?Coat|Cisco Umbrella|Kaspersky Anti-Virus Personal Root|AVG|Avast|ESET SSL Filter|BitDefender Personal|DO_NOT_TRUST') {
                $null = $reasons.Add('The subject name matches a known TLS-interception product - traffic to every HTTPS site can be decrypted by whatever holds this key')
                $severity = 'Critical'
            }

            if ($certificate.NotBefore -gt (Get-Date).AddDays(-90)) {
                $null = $reasons.Add("The certificate was issued recently ($($certificate.NotBefore.ToString('yyyy-MM-dd')))")
            }
            if ($certificate.NotAfter -lt (Get-Date)) {
                $null = $reasons.Add("The certificate expired on $($certificate.NotAfter.ToString('yyyy-MM-dd')) and should have been removed")
            }
            if ($storeSpec.Location -eq 'CurrentUser') {
                $null = $reasons.Add('It sits in the per-user store, which can be written without administrator rights')
            }

            if ($reasons.Count -eq 0) { $null = $reasons.Add('The issuer is not one that ships with Windows or with mainstream software') }

            Add-Finding -Category $script:NetworkCategory -Check 'RootCertificates' -Severity $severity `
                        -Title "Unrecognised certificate authority in $($storeSpec.Label): $(Get-CommonName $subject)" `
                        -Detail (($reasons -join '; ') + '. A certificate in this store can vouch for any website on the internet, so software holding the matching private key can present a valid-looking certificate for your bank and no browser will warn you.') `
                        -Recommendation "If you cannot attribute this to software you installed (corporate VPN, antivirus with HTTPS scanning, a developer proxy), remove it: Get-ChildItem Cert:\$($storeSpec.Location)\$($storeSpec.Name)\$($certificate.Thumbprint) | Remove-Item" `
                        -Evidence ([ordered]@{
                            'Store'      = "Cert:\$($storeSpec.Location)\$($storeSpec.Name)"
                            'Subject'    = $subject
                            'Issuer'     = $issuer
                            'Thumbprint' = $certificate.Thumbprint
                            'Valid from' = $certificate.NotBefore
                            'Valid to'   = $certificate.NotAfter
                            'Self-signed'= $selfSigned
                        })
        }
    }
}

function Test-SharesAndFirewallRules {
    Write-ScanLog -Message 'Network shares and inbound firewall rules' -Level 'Step'

    try {
        $shares = @(Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -notmatch '^\w\$$' -and $_.Name -ne 'IPC$' -and $_.Name -ne 'ADMIN$' })
        foreach ($share in $shares) {
            $openTo = @()
            try {
                $openTo = @(Get-SmbShareAccess -Name $share.Name -ErrorAction Stop |
                            Where-Object { $_.AccessControlType -eq 'Allow' -and "$($_.AccountName)" -match 'Everyone|ANONYMOUS|Guests' })
            }
            catch { }

            $severity = if ($openTo.Count -gt 0) { 'High' } else { 'Low' }
            $detail = "The folder '$($share.Path)' is shared on the network as '$($share.Name)'. "
            if ($openTo.Count -gt 0) {
                $detail += 'It grants access to Everyone/Anonymous, so any device on the same network can reach it without credentials. This is a common route for ransomware to spread between machines.'
            }

            Add-Finding -Category $script:NetworkCategory -Check 'Shares' -Severity $severity `
                        -Title "SMB share '$($share.Name)' is published" `
                        -Detail $detail `
                        -Recommendation 'Remove shares you no longer use with Remove-SmbShare, and never grant Everyone write access on a machine that connects to public networks.' `
                        -Evidence ([ordered]@{
                            'Share' = $share.Name
                            'Path'  = $share.Path
                            'Open access grants' = if ($openTo.Count -gt 0) { (($openTo | ForEach-Object { "$($_.AccountName): $($_.AccessRight)" }) -join ', ') } else { 'none' }
                        })
        }
    }
    catch { }

    try {
        $rules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop |
                   Where-Object { "$($_.Profile)" -match 'Public|Any' })

        foreach ($rule in $rules) {
            $applicationFilter = $null
            try { $applicationFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop } catch { }
            $program = if ($applicationFilter) { "$($applicationFilter.Program)" } else { 'Any' }
            if ($program -eq 'Any' -or [string]::IsNullOrWhiteSpace($program)) { continue }

            $resolved  = Expand-PathVariables -Path $program
            $signature = Get-SignatureInfo -Path $resolved
            if ($signature.IsMicrosoft) { continue }

            $reasons = @(Test-SuspiciousPath -Path $resolved)
            if ($signature.Exists -and -not $signature.IsSigned) { $reasons += 'The allowed program is unsigned' }
            if (-not $signature.Exists) { $reasons += 'The allowed program no longer exists on disk (stale rule)' }
            if ($reasons.Count -eq 0) { continue }

            $portFilter = $null
            try { $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop } catch { }

            Add-Finding -Category $script:NetworkCategory -Check 'FirewallRules' -Severity 'High' `
                        -Title "Firewall rule '$($rule.DisplayName)' opens the public profile to an untrusted program" `
                        -Detail (($reasons -join '; ') + '. Inbound allow rules on the Public profile apply on untrusted networks such as cafe and hotel Wi-Fi.') `
                        -Recommendation "Remove the rule if you do not recognise it: Remove-NetFirewallRule -Name '$($rule.Name)'" `
                        -Evidence ([ordered]@{
                            'Rule'      = $rule.DisplayName
                            'Program'   = $resolved
                            'Profile'   = "$($rule.Profile)"
                            'Ports'     = if ($portFilter) { "$($portFilter.Protocol) $($portFilter.LocalPort)" } else { 'any' }
                            'Signature' = if ($signature.Exists) { "$($signature.Status) $($signature.Signer)" } else { 'file missing' }
                        })
        }
    }
    catch { }
}

function Test-NameResolutionExposure {
    Write-ScanLog -Message 'LLMNR / NetBIOS name resolution' -Level 'Step'

    $llmnr = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast'
    if ([int]$llmnr -ne 0) {
        Add-Finding -Category $script:NetworkCategory -Check 'NameResolution' -Severity 'Medium' `
                    -Title 'LLMNR multicast name resolution is enabled' `
                    -Detail 'When DNS fails, Windows shouts the hostname onto the local network and trusts whoever answers first. On a shared network an attacker answers every query and collects your NTLM credential hashes - a technique that needs no malware on your machine at all, so no antivirus can see it.' `
                    -Recommendation 'Create HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient and set EnableMulticast = 0 (DWORD).' `
                    -Evidence ([ordered]@{ 'EnableMulticast' = if ($null -eq $llmnr) { 'not set (enabled by default)' } else { $llmnr } })
    }

    $netbiosEnabled = New-Object System.Collections.ArrayList
    foreach ($interface in (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue)) {
        $option = Get-RegistryValue -Path $interface.PSPath -Name 'NetbiosOptions'
        # 0 = use DHCP setting, 1 = enabled, 2 = disabled
        if ([int]$option -ne 2) { $null = $netbiosEnabled.Add($interface.PSChildName) }
    }
    if ($netbiosEnabled.Count -gt 0) {
        Add-Finding -Category $script:NetworkCategory -Check 'NameResolution' -Severity 'Low' `
                    -Title "NetBIOS over TCP/IP is not disabled on $($netbiosEnabled.Count) interface(s)" `
                    -Detail 'NBT-NS has the same credential-relay weakness as LLMNR and is obsolete on any network that has working DNS.' `
                    -Recommendation 'Set NetbiosOptions = 2 for each interface under HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces, or disable NetBIOS in the adapter''s advanced TCP/IP settings.' `
                    -Evidence ([ordered]@{ 'Interfaces' = ($netbiosEnabled -join ', ') })
    }

    # WPAD resolves a proxy config from the network - same trust problem.
    $wpadDisabled = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Name 'DisableWpad'
    if ([int]$wpadDisabled -ne 1) {
        Add-Finding -Category $script:NetworkCategory -Check 'NameResolution' -Severity 'Low' `
                    -Title 'WPAD proxy auto-discovery is not disabled' `
                    -Detail 'WPAD asks the local network for proxy settings. Anyone able to answer that request can route all of your web traffic through themselves.' `
                    -Recommendation 'Set DisableWpad = 1 (DWORD) under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp, and turn off "Automatically detect settings" in proxy options.' `
                    -Evidence ([ordered]@{ 'DisableWpad' = if ($null -eq $wpadDisabled) { 'not set' } else { $wpadDisabled } })
    }
}

function Invoke-NetworkChecks {
    Invoke-Check -Name 'ListeningPorts'      -Body { Test-ListeningPorts }
    Invoke-Check -Name 'OutboundConnections' -Body { Test-OutboundConnections }
    Invoke-Check -Name 'HostsFile'           -Body { Test-HostsFile }
    Invoke-Check -Name 'DnsConfiguration'    -Body { Test-DnsConfiguration }
    Invoke-Check -Name 'ProxyConfiguration'  -Body { Test-ProxyConfiguration }
    Invoke-Check -Name 'RootCertificates'    -Body { Test-RootCertificates }
    Invoke-Check -Name 'SharesAndFirewall'   -Body { Test-SharesAndFirewallRules }
    Invoke-Check -Name 'NameResolution'      -Body { Test-NameResolutionExposure }
}
