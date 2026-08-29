#!/usr/bin/env python3
"""
Proxy Scanner — private code / public output split, with per-source stats
-----------------------------------------------------------------------------
This script lives in a PRIVATE repo (code + workflow never public). It:

  1. Fetches candidate HTTP proxies from HTTP_SOURCES and candidate SOCKS5
     proxies from SOCKS5_SOURCES below (add/remove/edit entries there —
     nothing else needs to change). Duplicate candidates are collapsed
     before testing starts (each protocol's candidate dict is keyed by
     ip:port), so the same proxy reported by several sources is only
     ever tested once per protocol.
  2. Reads back the previous run's healthy proxies from the PUBLIC
     output repo (plain GET of the raw file, no auth needed to read a
     public repo) and re-tests those too — separately for HTTP and
     SOCKS5.
  3. Tests every candidate ONCE with a real HTTP/HTTPS request through
     the proxy against TARGET_URL (https://www.gstatic.com/generate_204
     by default — a tiny endpoint that returns 204 with no body, the
     same kind of check v2rayNG's "real delay" test does) and times the
     full round trip. This is real traffic through the proxy, not just
     a TCP port-open check — a proxy that accepts a connection but
     can't actually relay a request will correctly fail here.
     (HTTP candidates via a plain HTTP(S) proxy request, SOCKS5
     candidates via a socks5h:// proxied request so DNS is also
     resolved through the proxy.)
  4. Keeps only the TOP_N (default 100) fastest survivors per protocol
     (sorted by measured round-trip latency, ascending) — everything
     else is dropped, even if it "passed".
  5. Looks up the country of each of those final survivors (via
     GEOIP_PROVIDERS, with automatic fallback to the next provider on
     failure/rate-limit) and appends a matching flag emoji to the
     remark, e.g. "زن زندگی آزادی 🇩🇪". If every provider fails for an
     IP, that entry just keeps the plain remark with no flag.
  6. Pushes survivors to HTTP_FILE_PATH and SOCKS5_FILE_PATH (two
     separate files) in the PUBLIC repo via the GitHub Contents API,
     one line each:
         http://ip:port#<remark + flag>   (HTTP file)
         socks://ip:port#<remark + flag>  (SOCKS5 file — v2rayNG-importable)
  7. Updates a "healthy proxies per source" Mermaid chart + table for
     EACH protocol in THIS (private) repo's local README.md, between
     their own <!-- STATS:HTTP:START/END --> and
     <!-- STATS:SOCKS5:START/END --> markers — this file stays local;
     the workflow commits it back to the private repo, it is never
     sent to the public repo. Stats are computed on the final
     published (top-N) set, not on every proxy that merely passed.

Only the proxy lists are ever visible to the public — the stats charts
stay private, along with the code and logs.

--------------------------------------------------------------------------
HOW TO ADD / REMOVE A SOURCE
--------------------------------------------------------------------------
Just edit HTTP_SOURCES / SOCKS5_SOURCES below. Each entry is one of:

    {"name": "...", "type": "api",  "url": "...", "params": {...}}
    {"name": "...", "type": "text", "url": "..."}   # plain ip:port list
    {"name": "...", "type": "html", "url": "..."}   # scraped off a page

Delete an entry to stop using that source, or copy one of the "text" /
"html" entries and change name/url to add a new one. The same "html"
(and "api") source can appear in both lists — some pages/APIs list
both HTTP and SOCKS5 proxies together, so re-scraping them for the
other protocol is fine and intentional.

--------------------------------------------------------------------------
Required environment variables (private repo's Actions secrets/vars):
    PUBLIC_REPO         e.g. "yourname/proxy-list-public"
    PUBLIC_REPO_TOKEN   fine-grained PAT, Contents: Read & write, scoped
                         ONLY to that public repo (GitHub secret)
    PUBLIC_BRANCH        default "main"
    HTTP_FILE_PATH       default "proxies/http.txt"    (path *inside the public repo*)
    SOCKS5_FILE_PATH     default "proxies/socks5.txt"  (path *inside the public repo*)
    README_PATH          default "README.md"           (LOCAL path in this repo — stays private)

Requires: requests, PySocks (for socks5h:// proxy testing)
    pip install requests pysocks
"""

import base64
import os
import re
import sys
import time
import concurrent.futures
from urllib.parse import quote

import requests

# ----------------------------- Sources -----------------------------
# Add, remove, or edit entries here — that's the only thing you need to
# touch to change what gets scanned.

HTTP_SOURCES = [
    {
        "name": "ProxyScrape",
        "type": "api",
        "url": "https://api.proxyscrape.com/v4/free-proxy-list/get",
        "params": {
            "request": "getproxies", "protocol": "http",
            "proxy_format": "protocolipport", "format": "text",
            "timeout": "10000", "country": "all", "ssl": "all", "anonymity": "all",
        },
    },
    {
        "name": "monosans/proxy-list",
        "type": "text",
        "url": "https://raw.githubusercontent.com/monosans/proxy-list/refs/heads/main/proxies/http.txt",
    },
    {
        "name": "ALIILAPRO/Proxy",
        "type": "text",
        "url": "https://raw.githubusercontent.com/ALIILAPRO/Proxy/refs/heads/main/http.txt",
    },
    {
        "name": "roosterkid/openproxylist",
        "type": "text",
        "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS.txt",
    },
    {
        "name": "proxifly/free-proxy-list",
        "type": "text",
        "url": "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/http/data.txt",
    },
    {
        "name": "TheSpeedX/PROXY-List",
        "type": "text",
        "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/http.txt",
    },
    {
        "name": "proxy-spider.com (Iran)",
        "type": "html",
        "url": "https://proxy-spider.com/proxies/locations/ir-iran-islamic-republic-of",
    },
    {
        "name": "premiumproxy.net (Iran)",
        "type": "html",
        "url": "https://premiumproxy.net/top-country-proxy-list/IR-Iran/",
    },
]

SOCKS5_SOURCES = [
    {
        "name": "ProxyScrape",
        "type": "api",
        "url": "https://api.proxyscrape.com/v4/free-proxy-list/get",
        "params": {
            "request": "getproxies", "protocol": "socks5",
            "proxy_format": "protocolipport", "format": "text",
            "timeout": "10000", "country": "all", "ssl": "all", "anonymity": "all",
        },
    },
    {
        "name": "monosans/proxy-list",
        "type": "text",
        "url": "https://raw.githubusercontent.com/monosans/proxy-list/refs/heads/main/proxies/socks5.txt",
    },
    {
        "name": "ALIILAPRO/Proxy",
        "type": "text",
        "url": "https://raw.githubusercontent.com/ALIILAPRO/Proxy/refs/heads/main/socks5.txt",
    },
    {
        "name": "roosterkid/openproxylist",
        "type": "text",
        "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/SOCKS5_RAW.txt",
    },
    {
        "name": "proxifly/free-proxy-list",
        "type": "text",
        "url": "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks5/data.txt",
    },
    {
        "name": "TheSpeedX/PROXY-List",
        "type": "text",
        "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks5.txt",
    },
    {
        "name": "proxy-spider.com (Iran)",
        "type": "html",
        "url": "https://proxy-spider.com/proxies/locations/ir-iran-islamic-republic-of",
    },
    {
        "name": "premiumproxy.net (Iran)",
        "type": "html",
        "url": "https://premiumproxy.net/top-country-proxy-list/IR-Iran/",
    },
]

PREVIOUS_SCAN_LABEL = "Previous scan (re-checked)"

TARGET_URL = "https://www.gstatic.com/generate_204"
MAX_THREADS = 150

# Single real HTTP/HTTPS request through the proxy (not a bare TCP/port
# check) — this is the round trip that gets timed. Same idea as v2rayNG's
# "real delay" test. Raise this if too many otherwise-fine proxies are
# timing out; lower it to be stricter about latency.
TIMEOUT = 8  # seconds

# Only the fastest TOP_N survivors (by measured real-request latency) get
# published, per protocol (so up to TOP_N HTTP + TOP_N SOCKS5 lines total).
TOP_N = 100

REMARK = "زن زندگی آزادی"

# Geolocation providers for the final flag-emoji step, tried in order with
# automatic fallback (a provider being down/rate-limited just moves on to
# the next one). Each needs a URL template with {ip} and the JSON field
# that holds the 2-letter country code.
GEOIP_PROVIDERS = [
    {"name": "ip.sb", "url": "https://api.ip.sb/geoip/{ip}", "field": "country_code"},
    {"name": "ip-api.com", "url": "http://ip-api.com/json/{ip}?fields=countryCode", "field": "countryCode"},
    {"name": "ipapi.co", "url": "https://ipapi.co/{ip}/json/", "field": "country_code"},
    {"name": "freeipapi.com", "url": "https://freeipapi.com/api/json/{ip}", "field": "countryCode"},
]

IP_PORT_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b")

GITHUB_API = "https://api.github.com"

HTTP_STATS_START = "<!-- STATS:HTTP:START -->"
HTTP_STATS_END = "<!-- STATS:HTTP:END -->"
SOCKS5_STATS_START = "<!-- STATS:SOCKS5:START -->"
SOCKS5_STATS_END = "<!-- STATS:SOCKS5:END -->"


def env(name, default=None, required=False):
    val = os.environ.get(name, default)
    if required and not val:
        print(f"Missing required environment variable: {name}", file=sys.stderr)
        sys.exit(1)
    return val


PUBLIC_REPO = env("PUBLIC_REPO", required=True)
PUBLIC_REPO_TOKEN = env("PUBLIC_REPO_TOKEN", required=True)
PUBLIC_BRANCH = env("PUBLIC_BRANCH", "main")
HTTP_FILE_PATH = env("HTTP_FILE_PATH", "proxies/http.txt")
SOCKS5_FILE_PATH = env("SOCKS5_FILE_PATH", "proxies/socks5.txt")
README_PATH = env("README_PATH", "README.md")


# ----------------------------- Fetching -----------------------------

def fetch_api_source(source):
    try:
        resp = requests.get(source["url"], params=source.get("params", {}), timeout=15)
        resp.raise_for_status()
        out = []
        for line in resp.text.splitlines():
            m = IP_PORT_RE.search(line.strip())
            if m:
                out.append(f"{m.group(1)}:{m.group(2)}")
        return out
    except Exception as e:
        print(f"[{source['name']}] failed: {e}")
        return []


def fetch_text_source(source):
    try:
        resp = requests.get(source["url"], timeout=20)
        resp.raise_for_status()
        out = []
        for line in resp.text.splitlines():
            line = line.strip()
            if not line:
                continue
            for scheme in ("https://", "http://", "socks5://", "socks4://"):
                if line.lower().startswith(scheme):
                    line = line[len(scheme):]
                    break
            m = IP_PORT_RE.search(line)
            if m:
                out.append(f"{m.group(1)}:{m.group(2)}")
        return out
    except Exception as e:
        print(f"[{source['name']}] failed: {e}")
        return []


def fetch_html_source(source):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    try:
        resp = requests.get(source["url"], headers=headers, timeout=20)
        resp.raise_for_status()
    except Exception as e:
        print(f"[{source['name']}] failed: {e}")
        return []

    out = []
    for line in resp.text.splitlines():
        m = IP_PORT_RE.search(line)
        if m:
            out.append(f"{m.group(1)}:{m.group(2)}")
    return list(dict.fromkeys(out))


FETCHERS = {
    "api": fetch_api_source,
    "text": fetch_text_source,
    "html": fetch_html_source,
}


def fetch_all_sources(sources):
    """Returns proxy_sources: dict[proxy] -> set of source names that
    reported it. This dict itself is the dedupe step — a proxy reported
    by several sources only ever gets one entry, so it's only tested
    once."""
    proxy_sources = {}
    for source in sources:
        fetcher = FETCHERS.get(source["type"])
        if not fetcher:
            print(f"[{source['name']}] unknown type '{source['type']}', skipping")
            continue
        found = fetcher(source)
        print(f"[{source['name']}] fetched {len(found)}")
        for proxy in found:
            proxy_sources.setdefault(proxy, set()).add(source["name"])
    return proxy_sources


def read_old_proxies(file_path, label):
    """Reads the currently-published file straight off the public repo's
    raw content (no auth needed — it's a public repo)."""
    url = f"https://raw.githubusercontent.com/{PUBLIC_REPO}/{PUBLIC_BRANCH}/{file_path}"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
    except Exception as e:
        print(f"[{label}] could not read previous file: {e}")
        return []

    out = []
    for line in resp.text.splitlines():
        m = IP_PORT_RE.search(line)
        if m:
            out.append(f"{m.group(1)}:{m.group(2)}")
    print(f"[{label}] {len(out)} previously-healthy proxies to re-check")
    return out


# ----------------------------- Testing -----------------------------

def check_proxy(proxy, protocol, timeout):
    """One real HTTP/HTTPS request through the proxy against TARGET_URL —
    this actually relays traffic (not just a TCP connect/port-open check),
    and the elapsed time is the real round-trip latency, same idea as
    v2rayNG's "real delay" test. TARGET_URL defaults to
    https://www.gstatic.com/generate_204, which replies 204 with no body
    on success (some proxies/CDNs may still hand back 200 instead — both
    count as a pass)."""
    proxy = proxy.strip()
    if not proxy:
        return None
    if protocol == "socks5":
        # socks5h:// resolves DNS through the proxy too, closer to how
        # a real client (v2rayNG etc.) would use it.
        proxies = {"http": f"socks5h://{proxy}", "https": f"socks5h://{proxy}"}
    else:
        proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
    try:
        start = time.time()
        r = requests.get(TARGET_URL, proxies=proxies, timeout=timeout)
        elapsed = time.time() - start
        if r.status_code in (200, 204):
            return (proxy, elapsed)
    except Exception:
        pass
    return None


def test_all(candidates, protocol, timeout):
    """Tests every candidate once. Returns dict: proxy -> real-request
    elapsed seconds, for the ones that passed."""
    results = {}
    if not candidates:
        print(f"[{protocol}] 0 candidates, skipping")
        return results
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {
            executor.submit(check_proxy, p, protocol, timeout): p for p in candidates
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                proxy, elapsed = result
                results[proxy] = elapsed
    print(f"[{protocol}] {len(results)}/{len(candidates)} passed (timeout={timeout}s)")
    return results


def lookup_country_code(ip):
    """Tries each GEOIP_PROVIDERS entry in order, falling back to the next
    on any failure or rate-limit. Returns a 2-letter country code or None
    if every provider failed."""
    for provider in GEOIP_PROVIDERS:
        try:
            resp = requests.get(
                provider["url"].format(ip=ip),
                timeout=6,
                headers={"User-Agent": "proxy-scanner-actions"},
            )
            if resp.status_code == 429 or not resp.ok:
                continue
            code = resp.json().get(provider["field"])
            if code and len(code) == 2:
                return code.upper()
        except Exception:
            continue
    return None


def flag_emoji(country_code):
    if not country_code or len(country_code) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in country_code.upper())


def geolocate_final(final_list):
    """final_list: list of (proxy, elapsed). Returns dict proxy -> flag
    emoji (empty string if lookup failed for that IP)."""
    flags = {}
    if not final_list:
        return flags
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = {
            executor.submit(lookup_country_code, proxy.split(":")[0]): proxy
            for proxy, _ in final_list
        }
        for future in concurrent.futures.as_completed(futures):
            proxy = futures[future]
            try:
                code = future.result()
            except Exception:
                code = None
            flags[proxy] = flag_emoji(code)
    return flags


def format_line(proxy, protocol, flag=""):
    ip, _, port = proxy.partition(":")
    remark = f"{REMARK} {flag}".strip() if flag else REMARK
    tag = quote(remark)
    if protocol == "socks5":
        return f"socks://{ip}:{port}#{tag}"
    return f"http://{ip}:{port}#{tag}"


# ----------------------------- Stats chart -----------------------------

def render_stats_block(counts, start_marker, end_marker, title):
    """counts: list of (source_name, healthy_count), already sorted."""
    lines = [start_marker, ""]
    lines.append(f"_Last updated: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}_")
    lines.append("")

    if counts:
        lines.append("```mermaid")
        lines.append("xychart-beta")
        lines.append(f'    title "{title}"')
        names = ", ".join(f'"{n}"' for n, _ in counts)
        lines.append(f"    x-axis [{names}]")
        lines.append('    y-axis "Healthy proxies"')
        values = ", ".join(str(c) for _, c in counts)
        lines.append(f"    bar [{values}]")
        lines.append("```")
        lines.append("")

    lines.append("| Source | Healthy proxies |")
    lines.append("|---|---|")
    for name, count in counts:
        lines.append(f"| {name} | {count} |")
    lines.append(f"| **Total unique** | **{sum(c for _, c in counts) if counts else 0}** |")
    lines.append("")
    lines.append(end_marker)
    return "\n".join(lines)


def merge_section(existing_text, start_marker, end_marker, block, header_if_missing):
    if start_marker in existing_text and end_marker in existing_text:
        start_idx = existing_text.rfind(start_marker)
        end_idx = existing_text.find(end_marker, start_idx)
        if end_idx == -1:
            return existing_text.rstrip() + "\n\n" + block + "\n"
        pre = existing_text[:start_idx]
        post = existing_text[end_idx + len(end_marker):]
        return pre + block + post
    # Markers not present yet — append a labeled section.
    sep = "\n\n" if existing_text.strip() else ""
    return existing_text.rstrip() + sep + header_if_missing + "\n\n" + block + "\n"


def merge_stats_into_readme(http_counts, socks5_counts):
    if os.path.exists(README_PATH):
        with open(README_PATH, "r", encoding="utf-8") as f:
            existing_text = f.read()
    else:
        existing_text = "# Proxy scanner stats (private)\n"

    http_block = render_stats_block(
        http_counts, HTTP_STATS_START, HTTP_STATS_END, "Healthy HTTP proxies per source"
    )
    existing_text = merge_section(
        existing_text, HTTP_STATS_START, HTTP_STATS_END, http_block, "## HTTP"
    )

    socks5_block = render_stats_block(
        socks5_counts, SOCKS5_STATS_START, SOCKS5_STATS_END, "Healthy SOCKS5 proxies per source"
    )
    existing_text = merge_section(
        existing_text, SOCKS5_STATS_START, SOCKS5_STATS_END, socks5_block, "## SOCKS5"
    )

    with open(README_PATH, "w", encoding="utf-8") as f:
        f.write(existing_text)
    print(f"[readme] updated local stats in {README_PATH}")


# ----------------------------- GitHub Contents API -----------------------------

def github_get_file(path):
    url = f"{GITHUB_API}/repos/{PUBLIC_REPO}/contents/{path}"
    headers = {
        "Authorization": f"Bearer {PUBLIC_REPO_TOKEN}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "proxy-scanner-actions",
    }
    resp = requests.get(url, headers=headers, params={"ref": PUBLIC_BRANCH}, timeout=15)
    if resp.status_code == 404:
        return None
    if not resp.ok:
        print(f"[github] GET {path} failed: {resp.status_code} {resp.text}", file=sys.stderr)
    resp.raise_for_status()
    data = resp.json()
    text = base64.b64decode(data["content"]).decode("utf-8")
    return {"text": text, "sha": data["sha"]}


def github_write_file(path, content, message):
    existing = github_get_file(path)
    url = f"{GITHUB_API}/repos/{PUBLIC_REPO}/contents/{path}"
    headers = {
        "Authorization": f"Bearer {PUBLIC_REPO_TOKEN}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "proxy-scanner-actions",
        "Content-Type": "application/json",
    }
    body = {
        "message": message,
        "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
        "branch": PUBLIC_BRANCH,
    }
    if existing:
        body["sha"] = existing["sha"]

    resp = requests.put(url, headers=headers, json=body, timeout=20)
    if not resp.ok:
        print(f"[github] write failed for {path}: {resp.status_code} {resp.text}", file=sys.stderr)
        resp.raise_for_status()
    else:
        print(f"[github] wrote {path} ({len(content)} bytes)")


def verify_public_repo_access():
    """Fail fast (before spending 15-20 min testing proxies) if PUBLIC_REPO /
    PUBLIC_REPO_TOKEN are misconfigured."""
    url = f"{GITHUB_API}/repos/{PUBLIC_REPO}"
    headers = {
        "Authorization": f"Bearer {PUBLIC_REPO_TOKEN}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "proxy-scanner-actions",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=15)
    except Exception as e:
        print(f"Could not reach GitHub API: {e}", file=sys.stderr)
        sys.exit(1)

    if resp.status_code == 401:
        print("PUBLIC_REPO_TOKEN is invalid or expired.", file=sys.stderr)
        sys.exit(1)
    if resp.status_code == 404:
        print(f"PUBLIC_REPO '{PUBLIC_REPO}' not found, or the token can't see it "
              f"(check the repo name and the token's repository access).", file=sys.stderr)
        sys.exit(1)
    if not resp.ok:
        print(f"Unexpected error checking PUBLIC_REPO: {resp.status_code} {resp.text}", file=sys.stderr)
        sys.exit(1)

    perms = resp.json().get("permissions", {})
    if not perms.get("push", False):
        print(f"Token can read '{PUBLIC_REPO}' but lacks write/push access — "
              f"give it 'Contents: Read and write' permission on that repo.", file=sys.stderr)
        sys.exit(1)

    print(f"[preflight] write access to {PUBLIC_REPO} confirmed")


# ----------------------------- Main -----------------------------

def main():
    print("Starting proxy scan (GitHub Actions run)...\n")

    verify_public_repo_access()

    # ---- gather candidates per protocol (each dict is already deduped) ----
    print("\n=== Fetching HTTP candidates ===")
    http_sources = fetch_all_sources(HTTP_SOURCES)
    for proxy in read_old_proxies(HTTP_FILE_PATH, f"HTTP {PREVIOUS_SCAN_LABEL}"):
        http_sources.setdefault(proxy, set()).add(PREVIOUS_SCAN_LABEL)

    print("\n=== Fetching SOCKS5 candidates ===")
    socks5_sources = fetch_all_sources(SOCKS5_SOURCES)
    for proxy in read_old_proxies(SOCKS5_FILE_PATH, f"SOCKS5 {PREVIOUS_SCAN_LABEL}"):
        socks5_sources.setdefault(proxy, set()).add(PREVIOUS_SCAN_LABEL)

    print(f"\nCandidates to test: {len(http_sources)} HTTP, {len(socks5_sources)} SOCKS5")

    print("\n=== Testing HTTP candidates (real request) ===")
    http_results = test_all(list(http_sources.keys()), "http", TIMEOUT)
    print("\n=== Testing SOCKS5 candidates (real request) ===")
    socks5_results = test_all(list(socks5_sources.keys()), "socks5", TIMEOUT)

    working_http = sorted(http_results.items(), key=lambda x: x[1])[:TOP_N]
    working_socks5 = sorted(socks5_results.items(), key=lambda x: x[1])[:TOP_N]

    print(f"\nHTTP: {len(working_http)} kept (top {TOP_N} by real-request latency, fastest first)")
    print(f"SOCKS5: {len(working_socks5)} kept (top {TOP_N} by real-request latency, fastest first)")

    print("\n=== Geolocating final selections ===")
    http_flags = geolocate_final(working_http)
    socks5_flags = geolocate_final(working_socks5)

    def per_source_counts(working, proxy_sources):
        counts = {}
        for proxy, _elapsed in working:
            for name in proxy_sources.get(proxy, ()):
                counts[name] = counts.get(name, 0) + 1
        return sorted(counts.items(), key=lambda x: x[1], reverse=True)

    http_counts_sorted = per_source_counts(working_http, http_sources)
    socks5_counts_sorted = per_source_counts(working_socks5, socks5_sources)

    http_lines = [format_line(p, "http", http_flags.get(p, "")) for p, _ in working_http]
    socks5_lines = [format_line(p, "socks5", socks5_flags.get(p, "")) for p, _ in working_socks5]

    try:
        github_write_file(
            HTTP_FILE_PATH,
            "\n".join(http_lines) + ("\n" if http_lines else ""),
            f"proxy scan: {len(http_lines)} live HTTP proxies",
        )
        github_write_file(
            SOCKS5_FILE_PATH,
            "\n".join(socks5_lines) + ("\n" if socks5_lines else ""),
            f"proxy scan: {len(socks5_lines)} live SOCKS5 proxies",
        )
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)

    merge_stats_into_readme(http_counts_sorted, socks5_counts_sorted)

    print("\nDone.")


if __name__ == "__main__":
    main()
