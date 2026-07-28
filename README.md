# Argus — PC security scanner

A read-only Windows auditor for the classes of problem Microsoft Defender does not look for.

Defender is very good at answering **"is this file malware?"**. It has no opinion on **"has something changed the way this machine behaves?"** — and that second question covers most of what actually goes wrong on a personal PC. Argus answers the second one.

Everything it reports is a *configuration* fact: a Defender exclusion, a scheduled task, a proxy setting, a certificate, a file permission. None of it triggers an antivirus detection, because none of it is a virus. That is exactly why it is worth checking.

**Argus never changes anything.** Every finding tells you the command *you* would run to fix it, so you can read it first.

---

## Running it

You need Windows. PowerShell is already installed — there is nothing to download or set up.

### 1. Get the file onto your PC

Save **`ArgusScan-Standalone.ps1`** anywhere convenient (Downloads is fine). It is the whole scanner in one file.

### 2. Open PowerShell as Administrator

Press <kbd>Win</kbd>, type `powershell`, then right-click **Windows PowerShell** → **Run as administrator**.

Elevation matters. Without it, the WMI persistence, service permission and user-rights checks are skipped — and those are some of the highest-value ones.

### 3. Run it

Paste this, adjusting the path to wherever you saved the file:

```powershell
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\Downloads\ArgusScan-Standalone.ps1"
```

Windows blocks downloaded scripts by default; `-ExecutionPolicy Bypass` applies only to this one run and changes nothing permanently.

If Windows says the file is blocked, unblock it once:

```powershell
Unblock-File "$env:USERPROFILE\Downloads\ArgusScan-Standalone.ps1"
```

A scan takes roughly one to three minutes — most of it spent verifying digital signatures.

### 4. Read the report

An HTML report lands on your **Desktop** as `ArgusScan-<date>.html`. Double-click it. It opens in your browser, works offline, and lets you filter by severity or search the findings.

---

## What it checks

### Persistence & autoruns
Every location code can register itself to run again, graded on the target's digital signature, where it lives on disk, and the shape of its command line.

Run/RunOnce keys (machine and every user hive) · startup folders · scheduled tasks, including hidden ones and hijacked entries inside the Microsoft task tree · services and svchost `ServiceDll` entries · **WMI event subscriptions** · IFEO debugger hijacks and SilentProcessExit triggers · Winlogon `Shell`/`Userinit`/`Notify` · `AppInit_DLLs` and `AppCertDlls` · **LSA security packages** · per-user COM hijacks that shadow machine-wide registrations · PowerShell profiles · Browser Helper Objects, Active Setup, screensaver · `.exe` file-association hijacks · `BootExecute` · unsigned kernel drivers · netsh helper and print monitor DLLs.

Two of those deserve calling out. **WMI event subscriptions** live in the CIM repository rather than on disk, so file scanning cannot see them at all. **LSA packages** are DLLs loaded into `lsass.exe`, the process holding your credentials — an unexpected entry there is a credential-theft implant.

### Defender tampering & hardening
Whether Defender has been quietly weakened, and how much attack surface the OS leaves open.

Real-time / behaviour / cloud protection state · tamper protection · signature age · **exclusion paths, processes, extensions and IPs** · Attack Surface Reduction rules not in Block mode · Group Policy overrides forcing Defender off · security service health · **WDigest cleartext credential caching** · LSA Protection (RunAsPPL) · UAC level and `LocalAccountTokenFilterPolicy` · SMBv1 and SMB signing · RDP exposure and NLA · firewall profiles · Secure Boot · BitLocker · script block logging · PowerShell v2 (an AMSI bypass) · `AlwaysInstallElevated` · AutoRun · patch level.

Exclusions are the highest-value item here. Adding one is a supported operation that produces no alert, and everything inside it becomes permanently invisible to Defender.

### Network & trust
What is listening, what is talking out — attributed to the responsible binary — and the plumbing that decides where traffic goes and who it trusts.

Listening ports mapped to owning process and signature · outbound connections from unsigned binaries · **hosts file tampering**, with specific attention to blackholed antivirus and update domains · DNS servers and NRPT policy rules · **proxy and PAC (`AutoConfigURL`) hijacks** · **the trusted root certificate store** · SMB shares open to Everyone · inbound firewall rules exposing untrusted programs on public networks · LLMNR, NetBIOS and WPAD.

A rogue root certificate is the standout. It can vouch for any website on the internet, so whoever holds the matching key can present a valid-looking certificate for your bank and no browser will warn you. Installing one is not malware and triggers no detection.

### Accounts & privilege paths
If a standard user — or malware running as one — is on this machine, what lets it become SYSTEM without needing an exploit?

Local accounts, including **accounts hidden from the sign-in screen** · Guest and built-in Administrator state · password and lockout policy · **unquoted service paths** with writable prefixes · **service binaries and directories writable by non-administrators** · service security descriptors granting `SERVICE_CHANGE_CONFIG` to ordinary users · **writable directories in the system PATH** · SYSTEM scheduled tasks pointing at writable targets · saved credentials in Credential Manager · dangerous user-rights assignments such as `SeDebugPrivilege`.

---

## Reading the results

| Severity | What it means |
|---|---|
| **Critical** | Act now. Either an indicator of active compromise, or something that hands full control of the machine to anyone who asks. |
| **High** | Investigate today. A real weakness, or unexplained software. |
| **Medium** | Worth fixing. Hardening gaps that widen your attack surface. |
| **Low** | Tidy up when convenient. |
| **Info** | Context, so you have a baseline to compare against later. |

**A finding is a prompt to check something, not proof of compromise.** Software you installed yourself accounts for most Medium and Low results — a VPN client legitimately installs a root certificate, a game launcher legitimately adds a Run key. The value is in the ones you *cannot* explain.

The most useful way to use this is twice: scan now to establish a baseline, then scan again later and compare. Something new appearing in Critical or High between two scans is a much stronger signal than any single result.

---

## Options

```powershell
# Everything, report on the Desktop (the default)
.\ArgusScan-Standalone.ps1

# Just one or two areas
.\ArgusScan-Standalone.ps1 -Categories Persistence,Defender

# Only show High and Critical on screen (the report still contains everything)
.\ArgusScan-Standalone.ps1 -MinimumSeverity High

# Write the report somewhere specific, plus JSON for comparing two scans
.\ArgusScan-Standalone.ps1 -OutputPath C:\scans\today.html -Json

# Console output only, no files
.\ArgusScan-Standalone.ps1 -NoReport
```

| Parameter | Description |
|---|---|
| `-OutputPath` | Where to write the HTML report. Defaults to a timestamped file on the Desktop. |
| `-Categories` | `Persistence`, `Defender`, `Network`, `Accounts`, or `All` (default). |
| `-Json` | Also write a `.json` file next to the HTML, for diffing scans. |
| `-MinimumSeverity` | Lowest severity printed to the console. Default `Low`. |
| `-NoReport` | Console only, write no files. |
| `-Quiet` | Suppress per-finding console output; keep the summary. |

Exit codes, if you want to run this from a scheduled task: `0` clean · `1` low/medium · `2` high · `3` critical.

---

## Repository layout

The standalone file is generated. If you want to read or modify the code, work with the sources:

```
Invoke-PCScan.ps1            Entry point: parameters, orchestration, output
lib/Core.ps1                 Finding model, signature caching, path forensics, ACL checks
lib/Checks.Persistence.ps1   Autoruns and persistence
lib/Checks.Defender.ps1      Defender health, tampering, OS hardening
lib/Checks.Network.ps1       Exposure, traffic, trust store
lib/Checks.Accounts.ps1      Accounts and privilege escalation paths
lib/Report.ps1               HTML and JSON rendering
build/Build-Standalone.ps1   Bundles the above into ArgusScan-Standalone.ps1
ArgusScan-Standalone.ps1     Generated single-file build — run this one
```

Run `.\Invoke-PCScan.ps1` to use the multi-file version directly (keep it next to `lib/`). After editing anything under `lib/`, regenerate the bundle:

```powershell
.\build\Build-Standalone.ps1
```

Adding a check means writing a `Test-Something` function that calls `Add-Finding`, then registering it in that file's `Invoke-*Checks` function via `Invoke-Check`, which isolates failures so one broken check never aborts a scan.

---

## Limits worth knowing

- **This is not an antivirus.** It has no signatures and does not detect malware by content. Keep Defender enabled alongside it.
- **Command-line and script-content pattern matching can be defeated deliberately.** Checks for things like `FromBase64String` or `IEX` are literal text/regex matches against a command line or a referenced script's content. PowerShell's own syntax defeats this trivially — backtick-escaping between any two characters (`I`E`X`), string concatenation, or the `-f` format operator all still execute the same code without containing the literal substring being matched. Reliably catching this needs AST-level analysis of the actual parsed script, not text patterns. Treat a clean result from these specific checks as "nothing obvious," not "definitely clean."
- **Heuristics produce false positives.** Unsigned binaries in unusual folders are common in legitimate indie and open-source software.
- **A rootkit can lie to it.** Argus asks Windows questions through normal APIs. Kernel-level malware can answer falsely. If you have real reason to suspect compromise, scan the disk offline from separate boot media.
- **Not elevated means not complete.** The report states this at the top when it applies.

Requires Windows PowerShell 5.1 (present on Windows 10 and 11 by default) or PowerShell 7+.
