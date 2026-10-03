# log4j-scan (updated edition)

A fully automated, accurate, and extensive scanner for finding **Apache Log4Shell**
(CVE-2021-44228), its patch bypasses (**CVE-2021-45046**, **CVE-2021-45105**,
**CVE-2021-44827**) and related lookup-injection RCEs such as **Text4Shell**
(CVE-2022-42889) — with a **user-initiated live CVE update engine**.

This tool is based on the original [FullHunt log4j-scan](https://github.com/fullhunt/log4j-scan)
design (`log4j-scan.py` in this repo) and extends it according to the latest known
vulnerabilities. It keeps everything from the original scanner:

- Support for lists of URLs.
- Fuzzing of 60+ HTTP request headers (`headers.txt`).
- Fuzzing of HTTP POST (url-encoded) and JSON body parameters.
- DNS OOB callback verification via `interact.sh` / `dnslog.cn` or a custom callback host.
- WAF-bypass payload sets.

## What's new in the updated scanner

| Feature | Command |
|---|---|
| **Live CVE updates initiated by the user** | `--update-cves` |
| Browse the knowledge base | `--list-cves` |
| Test specific CVEs from the database | `--test-cve CVE-2021-44228,CVE-2021-45046` |
| Test every tracked CVE | `--test-all-cves` |
| Custom/alternative CVE database file | `--cve-db`, `--cve-db-out` |
| Faster NVD queries (optional) | `--nvd-api-key` or `NVD_API_KEY` env var |
| Resilient OOB callbacks | interact.sh server fallback list + `INTERACTSH_SERVER` env var |

### How `--update-cves` works

When invoked by the user, the scanner:

1. **Queries the NVD API 2.0** (`services.nvd.nist.gov`) for all recent
   Log4j/Log4Shell-related CVE records — titles, severities and CVSS scores —
   including brand-new CVEs that did not exist when this tool was bundled
   (e.g. the 2025/2026 Apache Log4j 1.x SMTPS hostname-verification CVEs).
2. **Refreshes metadata** for the known curated CVEs.
3. **Pulls fresh detection payloads** from curated community feeds
   (e.g. `trickest/log4j` obfuscated JNDI payload lists), normalising them into
   the scanner's `{{callback_host}}/{{random}}` templating format.
4. **Merges** everything into `cve_database.updated.json` next to the script.
   All future scans automatically prefer the newer database. Newly discovered
   CVEs are added but marked `default: false` so scans stay safe-by-default;
   opt them in with `--test-cve <ID>` or `--test-all-cves`.

The bundled offline knowledge base lives in `cvedb/cve_database.json`, so the
scanner works fully offline until you choose to update it.

## Installation

```shell
pip3 install -r requirements.txt
```

## Usage

```text
$ python3 log4j-scan-updated.py -h
usage: log4j-scan-updated.py [-h] [-u URL] [-p PROXY] [-l USEDLIST] [--request-type REQUEST_TYPE]
    [--headers-file HEADERS_FILE] [--run-all-tests] [--exclude-user-agent-fuzzing] [--wait-time WAIT_TIME]
    [--waf-bypass] [--custom-waf-bypass-payload CUSTOM_WAF_BYPASS_PAYLOAD] [--test-CVE-2021-45046]
    [--test-CVE-2022-42889] [--test-cve TEST_CVE] [--test-all-cves] [--list-cves] [--update-cves]
    [--nvd-api-key NVD_API_KEY] [--cve-db CVE_DB] [--cve-db-out CVE_DB_OUT]
    [--dns-callback-provider DNS_CALLBACK_PROVIDER] [--custom-dns-callback-host CUSTOM_DNS_CALLBACK_HOST]
    [--disable-http-redirects]
```

### Update the CVE knowledge base (user-initiated)

```shell
$ python3 log4j-scan-updated.py --update-cves
[•] CVE update initiated by user. Querying NVD for the latest Log4j-related CVEs...
[•] NVD returned 34 Log4j-related CVE record(s).
[✓] CVE database updated -> cve_database.updated.json
    • Total CVEs tracked : 36
    • New CVEs added     : CVE-2017-5645, CVE-2019-17571, ... , CVE-2026-85656
    • Payloads merged      : 36 new detection payload(s)
```

### Inspect what will be scanned

```shell
$ python3 log4j-scan-updated.py --list-cves
```

### Scan a single URL (latest CVE set, default Log4Shell payloads)

```shell
$ python3 log4j-scan-updated.py -u https://target.example.com
```

### Scan a URL against several CVEs, including WAF-bypass payloads

```shell
$ python3 log4j-scan-updated.py -u https://target.example.com \
    --test-cve CVE-2021-44228,CVE-2021-45046,CVE-2021-45105 --waf-bypass
```

### Scan every tracked CVE across a URL list, all request methods

```shell
$ python3 log4j-scan-updated.py -l urls.txt --test-all-cves --run-all-tests
```

### Update first, then scan, in one shot

```shell
$ python3 log4j-scan-updated.py --update-cves -u https://target.example.com
```

## Legal Disclaimer

This project is made for educational and ethical testing purposes only. Usage of
this scanner for attacking targets without prior mutual consent is illegal. It is
the end user's responsibility to obey all applicable local, state and federal laws.
Developers assume no liability and are not responsible for any misuse or damage
caused by this program.

## License

MIT (same as the original FullHunt log4j-scan project).
