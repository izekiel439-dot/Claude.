<#
    Report.ps1 - Output rendering.

    Produces a single self-contained HTML file (no external assets, so it opens
    fine on an offline or quarantined machine), plus optional JSON for
    diffing two scans against each other.
#>

function ConvertTo-HtmlText {
    param([string]$Text)

    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

function Get-SeverityGuidance {
    param([string]$Severity)

    switch ($Severity) {
        'Critical' { 'Act now. Each of these either indicates active compromise or hands full control of the machine to anyone who asks.' }
        'High'     { 'Investigate today. Real weaknesses or unexplained software that materially increase your risk.' }
        'Medium'   { 'Worth fixing. Hardening gaps and configuration that widens the attack surface.' }
        'Low'      { 'Tidy up when convenient. Minor exposure or good-practice items.' }
        default    { 'Context only. Recorded so you have a baseline to compare against later.' }
    }
}

function New-HtmlReport {
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [Parameter(Mandatory)][object]$HostInfo,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][datetime]$StartedAt,
        [Parameter(Mandatory)][datetime]$FinishedAt,
        [object[]]$Errors = @(),
        [string[]]$ChecksRun = @()
    )

    $counts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
    foreach ($finding in $Findings) { $counts[$finding.Severity]++ }

    $duration = [int]($FinishedAt - $StartedAt).TotalSeconds
    $ordered  = @($Findings | Sort-Object Rank, Category, Title)

    $verdict = if ($counts.Critical -gt 0) {
        'Critical findings need your attention now'
    } elseif ($counts.High -gt 0) {
        'High-severity findings need investigation'
    } elseif ($counts.Medium -gt 0) {
        'No urgent issues; hardening gaps remain'
    } else {
        'Nothing urgent found on this pass'
    }

    $verdictClass = if ($counts.Critical -gt 0) { 'bad' } elseif ($counts.High -gt 0) { 'warn' } elseif ($counts.Medium -gt 0) { 'ok' } else { 'good' }

    # ---- head / style -----------------------------------------------------
    $style = @'
<style>
  :root {
    --bg: #f6f7f9; --panel: #ffffff; --ink: #16191d; --muted: #5c6570;
    --line: #e2e5ea; --accent: #2f6fed; --shadow: 0 1px 2px rgba(16,24,40,.06), 0 1px 3px rgba(16,24,40,.08);
    --crit: #b4232c; --crit-bg: #fdf0f0; --high: #c2410c; --high-bg: #fdf3ec;
    --med: #a16207; --med-bg: #fdf8e9; --low: #1d6fa5; --low-bg: #eef6fc;
    --info: #5c6570; --info-bg: #f2f4f6; --good: #17734a;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0f1216; --panel: #171b21; --ink: #e7eaee; --muted: #98a2b0;
      --line: #262c35; --accent: #6f9dff; --shadow: none;
      --crit: #ff8489; --crit-bg: #2a161a; --high: #ffab70; --high-bg: #2a1e15;
      --med: #e8c468; --med-bg: #272115; --low: #7cc2f0; --low-bg: #131f2a;
      --info: #98a2b0; --info-bg: #1c2128; --good: #5fd7a0;
    }
  }
  :root[data-theme="dark"] {
    --bg: #0f1216; --panel: #171b21; --ink: #e7eaee; --muted: #98a2b0;
    --line: #262c35; --accent: #6f9dff; --shadow: none;
    --crit: #ff8489; --crit-bg: #2a161a; --high: #ffab70; --high-bg: #2a1e15;
    --med: #e8c468; --med-bg: #272115; --low: #7cc2f0; --low-bg: #131f2a;
    --info: #98a2b0; --info-bg: #1c2128; --good: #5fd7a0;
  }
  :root[data-theme="light"] {
    --bg: #f6f7f9; --panel: #ffffff; --ink: #16191d; --muted: #5c6570;
    --line: #e2e5ea; --accent: #2f6fed; --shadow: 0 1px 2px rgba(16,24,40,.06), 0 1px 3px rgba(16,24,40,.08);
    --crit: #b4232c; --crit-bg: #fdf0f0; --high: #c2410c; --high-bg: #fdf3ec;
    --med: #a16207; --med-bg: #fdf8e9; --low: #1d6fa5; --low-bg: #eef6fc;
    --info: #5c6570; --info-bg: #f2f4f6; --good: #17734a;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--ink);
    font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    -webkit-font-smoothing: antialiased;
  }
  .wrap { max-width: 1080px; margin: 0 auto; padding: 32px 20px 80px; }
  header h1 { font-size: 26px; margin: 0 0 4px; letter-spacing: -.02em; }
  header .sub { color: var(--muted); font-size: 14px; margin: 0 0 22px; }
  .verdict {
    padding: 14px 18px; border-radius: 10px; font-weight: 600; margin-bottom: 22px;
    border: 1px solid var(--line); background: var(--panel); box-shadow: var(--shadow);
  }
  .verdict.bad  { border-left: 4px solid var(--crit); }
  .verdict.warn { border-left: 4px solid var(--high); }
  .verdict.ok   { border-left: 4px solid var(--med); }
  .verdict.good { border-left: 4px solid var(--good); }
  .verdict span { display: block; font-weight: 400; color: var(--muted); font-size: 13.5px; margin-top: 4px; }
  .tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; margin-bottom: 22px; }
  .tile {
    background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
    padding: 14px 16px; box-shadow: var(--shadow); cursor: pointer; text-align: left;
    font: inherit; color: inherit; transition: border-color .12s ease;
  }
  .tile:hover { border-color: var(--accent); }
  .tile[aria-pressed="true"] { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent); }
  .tile .n { font-size: 26px; font-weight: 650; letter-spacing: -.02em; display: block; line-height: 1.1; }
  .tile .l { font-size: 12px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }
  .tile.c .n { color: var(--crit); } .tile.h .n { color: var(--high); }
  .tile.m .n { color: var(--med); }  .tile.l2 .n { color: var(--low); } .tile.i .n { color: var(--info); }
  .meta { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 4px 16px; margin-bottom: 22px; box-shadow: var(--shadow); }
  .meta dl { display: grid; grid-template-columns: minmax(120px, max-content) 1fr; gap: 0 18px; margin: 12px 0; font-size: 13.5px; }
  .meta dt { color: var(--muted); } .meta dd { margin: 0; word-break: break-word; }
  .controls { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-bottom: 16px; }
  .controls input, .controls select {
    font: inherit; font-size: 14px; padding: 8px 11px; border-radius: 8px;
    border: 1px solid var(--line); background: var(--panel); color: var(--ink);
  }
  .controls input { flex: 1 1 240px; min-width: 0; }
  .controls button {
    font: inherit; font-size: 13px; padding: 8px 12px; border-radius: 8px; cursor: pointer;
    border: 1px solid var(--line); background: var(--panel); color: var(--ink);
  }
  .controls button:hover { border-color: var(--accent); }
  h2.cat { font-size: 13px; text-transform: uppercase; letter-spacing: .07em; color: var(--muted); margin: 28px 0 10px; }
  details.f {
    background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
    margin-bottom: 8px; box-shadow: var(--shadow); overflow: hidden;
  }
  details.f > summary { padding: 13px 16px; cursor: pointer; display: flex; gap: 11px; align-items: flex-start; list-style: none; }
  details.f > summary::-webkit-details-marker { display: none; }
  .badge {
    flex: none; font-size: 10.5px; font-weight: 700; letter-spacing: .05em; text-transform: uppercase;
    padding: 3px 7px; border-radius: 5px; margin-top: 2px; white-space: nowrap;
  }
  .s-Critical .badge { color: var(--crit); background: var(--crit-bg); }
  .s-High     .badge { color: var(--high); background: var(--high-bg); }
  .s-Medium   .badge { color: var(--med);  background: var(--med-bg); }
  .s-Low      .badge { color: var(--low);  background: var(--low-bg); }
  .s-Info     .badge { color: var(--info); background: var(--info-bg); }
  .s-Critical { border-left: 3px solid var(--crit); }
  .s-High     { border-left: 3px solid var(--high); }
  .s-Medium   { border-left: 3px solid var(--med); }
  .s-Low      { border-left: 3px solid var(--low); }
  .s-Info     { border-left: 3px solid var(--info); }
  .t { font-weight: 550; word-break: break-word; }
  .body { padding: 0 16px 16px 16px; border-top: 1px solid var(--line); }
  .body p { margin: 12px 0; }
  .body .rec { background: var(--info-bg); border-radius: 8px; padding: 11px 13px; font-size: 14px; }
  .body .rec strong { display: block; font-size: 11.5px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin-bottom: 4px; }
  table.ev { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 12px; }
  table.ev th, table.ev td { text-align: left; padding: 7px 9px; border-bottom: 1px solid var(--line); vertical-align: top; }
  table.ev th { width: 170px; color: var(--muted); font-weight: 500; white-space: nowrap; }
  table.ev td { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; word-break: break-all; }
  .scroll { overflow-x: auto; }
  .empty { text-align: center; color: var(--muted); padding: 40px 0; }
  footer { margin-top: 44px; padding-top: 18px; border-top: 1px solid var(--line); color: var(--muted); font-size: 12.5px; }
  footer p { margin: 6px 0; }
  .theme { position: fixed; top: 14px; right: 14px; }
</style>
'@

    $script_ = @'
<script>
  (function () {
    var q = document.getElementById('q');
    var sev = document.getElementById('sev');
    var tiles = Array.prototype.slice.call(document.querySelectorAll('.tile'));
    var items = Array.prototype.slice.call(document.querySelectorAll('details.f'));
    var groups = Array.prototype.slice.call(document.querySelectorAll('.group'));
    var empty = document.getElementById('empty');

    function apply() {
      var text = (q.value || '').toLowerCase();
      var want = sev.value;
      var shown = 0;
      items.forEach(function (el) {
        var okSev = (want === 'all') || (el.dataset.sev === want);
        var okTxt = !text || el.dataset.search.indexOf(text) !== -1;
        var on = okSev && okTxt;
        el.style.display = on ? '' : 'none';
        if (on) shown++;
      });
      groups.forEach(function (g) {
        var any = Array.prototype.some.call(g.querySelectorAll('details.f'), function (el) {
          return el.style.display !== 'none';
        });
        g.style.display = any ? '' : 'none';
      });
      tiles.forEach(function (t) { t.setAttribute('aria-pressed', String(t.dataset.sev === want)); });
      empty.style.display = shown ? 'none' : '';
    }

    q.addEventListener('input', apply);
    sev.addEventListener('change', apply);
    tiles.forEach(function (t) {
      t.addEventListener('click', function () {
        sev.value = (sev.value === t.dataset.sev) ? 'all' : t.dataset.sev;
        apply();
      });
    });
    document.getElementById('expand').addEventListener('click', function () {
      items.forEach(function (el) { if (el.style.display !== 'none') el.open = true; });
    });
    document.getElementById('collapse').addEventListener('click', function () {
      items.forEach(function (el) { el.open = false; });
    });
    document.getElementById('theme').addEventListener('click', function () {
      var root = document.documentElement;
      var now = root.getAttribute('data-theme');
      if (!now) {
        now = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
      }
      root.setAttribute('data-theme', now === 'dark' ? 'light' : 'dark');
    });
    apply();
  })();
</script>
'@

    # ---- summary tiles ----------------------------------------------------
    $tiles = @"
<div class="tiles">
  <button type="button" class="tile c"  data-sev="Critical" aria-pressed="false"><span class="n">$($counts.Critical)</span><span class="l">Critical</span></button>
  <button type="button" class="tile h"  data-sev="High"     aria-pressed="false"><span class="n">$($counts.High)</span><span class="l">High</span></button>
  <button type="button" class="tile m"  data-sev="Medium"   aria-pressed="false"><span class="n">$($counts.Medium)</span><span class="l">Medium</span></button>
  <button type="button" class="tile l2" data-sev="Low"      aria-pressed="false"><span class="n">$($counts.Low)</span><span class="l">Low</span></button>
  <button type="button" class="tile i"  data-sev="Info"     aria-pressed="false"><span class="n">$($counts.Info)</span><span class="l">Info</span></button>
</div>
"@

    # ---- host metadata ----------------------------------------------------
    $errorNote = if ($Errors.Count -gt 0) {
        "$($Errors.Count) check(s) could not complete: " + (ConvertTo-HtmlText ((($Errors | ForEach-Object { $_.Check }) -join ', ')))
    } else { 'All checks completed' }

    $meta = @"
<div class="meta">
  <dl>
    <dt>Computer</dt><dd>$(ConvertTo-HtmlText $HostInfo.ComputerName) &mdash; $(ConvertTo-HtmlText $HostInfo.Manufacturer) $(ConvertTo-HtmlText $HostInfo.Model)</dd>
    <dt>Operating system</dt><dd>$(ConvertTo-HtmlText $HostInfo.OS) (build $(ConvertTo-HtmlText $HostInfo.OSVersion))</dd>
    <dt>Scanned as</dt><dd>$(ConvertTo-HtmlText $HostInfo.UserName) &mdash; $(if ($HostInfo.Elevated) { 'elevated' } else { '<strong>not elevated, some checks were skipped</strong>' })</dd>
    <dt>Domain</dt><dd>$(ConvertTo-HtmlText $HostInfo.Domain)</dd>
    <dt>Last boot</dt><dd>$(ConvertTo-HtmlText "$($HostInfo.LastBoot)")</dd>
    <dt>Scan started</dt><dd>$($StartedAt.ToString('yyyy-MM-dd HH:mm:ss')) (took ${duration}s, $($ChecksRun.Count) checks)</dd>
    <dt>Coverage</dt><dd>$errorNote</dd>
  </dl>
</div>
"@

    # ---- findings ---------------------------------------------------------
    $sections = New-Object System.Text.StringBuilder

    if ($ordered.Count -eq 0) {
        $null = $sections.AppendLine('<p class="empty">No findings were recorded.</p>')
    }

    foreach ($category in ($ordered | Group-Object Category | Sort-Object { $script:SeverityRank[($_.Group | Sort-Object Rank | Select-Object -First 1).Severity] })) {
        $null = $sections.AppendLine("<section class=""group""><h2 class=""cat"">$(ConvertTo-HtmlText $category.Name) &middot; $($category.Count)</h2>")

        foreach ($finding in ($category.Group | Sort-Object Rank, Title)) {
            $searchBlob = (("$($finding.Title) $($finding.Detail) $($finding.Check) " +
                            (($finding.Evidence | ForEach-Object { "$($_.Name) $($_.Value)" }) -join ' ')).ToLowerInvariant())

            $evidenceRows = New-Object System.Text.StringBuilder
            foreach ($pair in $finding.Evidence) {
                $null = $evidenceRows.AppendLine("<tr><th>$(ConvertTo-HtmlText $pair.Name)</th><td>$(ConvertTo-HtmlText $pair.Value)</td></tr>")
            }
            $evidenceTable = if ($finding.Evidence.Count -gt 0) {
                "<div class=""scroll""><table class=""ev"">$($evidenceRows.ToString())</table></div>"
            } else { '' }

            $recommendation = if ($finding.Recommendation) {
                "<p class=""rec""><strong>What to do</strong>$(ConvertTo-HtmlText $finding.Recommendation)</p>"
            } else { '' }

            $null = $sections.AppendLine(@"
<details class="f s-$($finding.Severity)" data-sev="$($finding.Severity)" data-search="$(ConvertTo-HtmlText $searchBlob)">
  <summary><span class="badge">$($finding.Severity)</span><span class="t">$(ConvertTo-HtmlText $finding.Title)</span></summary>
  <div class="body">
    <p>$(ConvertTo-HtmlText $finding.Detail)</p>
    $recommendation
    $evidenceTable
  </div>
</details>
"@)
        }
        $null = $sections.AppendLine('</section>')
    }

    # ---- assemble ---------------------------------------------------------
    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Argus scan &mdash; $(ConvertTo-HtmlText $HostInfo.ComputerName)</title>
$style
</head>
<body>
<div class="controls theme"><button type="button" id="theme">Theme</button></div>
<div class="wrap">
<header>
  <h1>Argus host scan</h1>
  <p class="sub">Configuration, persistence and exposure audit &mdash; the classes of problem an antivirus engine does not look for.</p>
</header>

<div class="verdict $verdictClass">
  $verdict
  <span>$(ConvertTo-HtmlText (Get-SeverityGuidance ($(if ($counts.Critical) { 'Critical' } elseif ($counts.High) { 'High' } elseif ($counts.Medium) { 'Medium' } elseif ($counts.Low) { 'Low' } else { 'Info' }))))</span>
</div>

$tiles
$meta

<div class="controls">
  <input type="search" id="q" placeholder="Filter findings by text, path, registry key...">
  <select id="sev">
    <option value="all">All severities</option>
    <option value="Critical">Critical</option>
    <option value="High">High</option>
    <option value="Medium">Medium</option>
    <option value="Low">Low</option>
    <option value="Info">Info</option>
  </select>
  <button type="button" id="expand">Expand all</button>
  <button type="button" id="collapse">Collapse all</button>
</div>

$($sections.ToString())
<p class="empty" id="empty" style="display:none">Nothing matches the current filter.</p>

<footer>
  <p>Argus reports posture and anomalies. It does not identify malware by signature &mdash; keep Microsoft Defender enabled alongside it.</p>
  <p>Findings are heuristic. A flagged item is a prompt to check something, not proof of compromise; software you installed yourself accounts for most non-critical results.</p>
  <p>Generated $($FinishedAt.ToString('yyyy-MM-dd HH:mm:ss')) on $(ConvertTo-HtmlText $HostInfo.ComputerName) &middot; PowerShell $(ConvertTo-HtmlText $HostInfo.PSVersion)</p>
</footer>
</div>
$script_
</body>
</html>
"@

    $directory = Split-Path $OutputPath -Parent
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        $null = New-Item -ItemType Directory -Path $directory -Force
    }
    Set-Content -LiteralPath $OutputPath -Value $html -Encoding UTF8
    return $OutputPath
}

function New-JsonReport {
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [Parameter(Mandatory)][object]$HostInfo,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][datetime]$StartedAt,
        [Parameter(Mandatory)][datetime]$FinishedAt,
        [object[]]$Errors = @(),
        [string[]]$ChecksRun = @()
    )

    $payload = [ordered]@{
        tool       = 'Argus'
        version    = $script:ArgusVersion
        startedAt  = $StartedAt.ToString('o')
        finishedAt = $FinishedAt.ToString('o')
        host       = $HostInfo
        checksRun  = @($ChecksRun)
        errors     = @($Errors)
        summary    = [ordered]@{
            total    = $Findings.Count
            critical = @($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
            high     = @($Findings | Where-Object { $_.Severity -eq 'High' }).Count
            medium   = @($Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
            low      = @($Findings | Where-Object { $_.Severity -eq 'Low' }).Count
            info     = @($Findings | Where-Object { $_.Severity -eq 'Info' }).Count
        }
        findings   = @($Findings | Sort-Object Rank, Category, Title)
    }

    $directory = Split-Path $OutputPath -Parent
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        $null = New-Item -ItemType Directory -Path $directory -Force
    }
    $payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    return $OutputPath
}

function Write-ConsoleSummary {
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [Parameter(Mandatory)][object]$HostInfo,
        [object[]]$Errors = @()
    )

    $counts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
    foreach ($finding in $Findings) { $counts[$finding.Severity]++ }

    Write-Host ''
    Write-Host ('-' * 66) -ForegroundColor DarkGray
    Write-Host ' SCAN SUMMARY' -ForegroundColor White
    Write-Host ('-' * 66) -ForegroundColor DarkGray
    Write-Host ("  Critical : {0}" -f $counts.Critical) -ForegroundColor $(if ($counts.Critical) { 'Magenta' } else { 'DarkGray' })
    Write-Host ("  High     : {0}" -f $counts.High)     -ForegroundColor $(if ($counts.High)     { 'Red' }     else { 'DarkGray' })
    Write-Host ("  Medium   : {0}" -f $counts.Medium)   -ForegroundColor $(if ($counts.Medium)   { 'Yellow' }  else { 'DarkGray' })
    Write-Host ("  Low      : {0}" -f $counts.Low)      -ForegroundColor $(if ($counts.Low)      { 'Cyan' }    else { 'DarkGray' })
    Write-Host ("  Info     : {0}" -f $counts.Info)     -ForegroundColor DarkGray

    if (-not $HostInfo.Elevated) {
        Write-Host ''
        Write-Host '  Note: this scan was not elevated. WMI subscriptions, service' -ForegroundColor Yellow
        Write-Host '  descriptors and user-rights checks were limited or skipped.'  -ForegroundColor Yellow
        Write-Host '  Re-run from an administrator PowerShell prompt for full coverage.' -ForegroundColor Yellow
    }

    if ($Errors.Count -gt 0) {
        Write-Host ''
        Write-Host "  $($Errors.Count) check(s) could not complete:" -ForegroundColor Yellow
        foreach ($item in $Errors) { Write-Host "    - $($item.Check): $($item.Message)" -ForegroundColor DarkGray }
    }
}
