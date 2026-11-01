#!/usr/bin/env python3
"""
MyPEN - a basic security hygiene scanner for websites YOU OWN.

By default a full run does ALL of this:
  - security headers, cookie flags, TLS certificate/protocol
  - information leakage, CORS misconfiguration, commonly exposed files
  - same-origin crawl (up to --max-pages, default 20)
  - SQL injection detection (error/boolean/time-based) across crawled pages:
      GETgreSQL  = URL query params + GET-method forms
      POSTgreSQL = POST-method forms
      (--sqli is shorthand for both; --no-sqli skips both)
  - reflected XSS detection across crawled pages
  - open redirect detection on likely redirect parameters
  - risky HTTP methods check (PUT/DELETE/TRACE/CONNECT via OPTIONS)
  - common subdomain enumeration (DNS resolution, no requests sent to them)
  - TCP connect scan of common ports
  - outdated JS library detection
  - missing CSRF token field on POST forms
  - writes mypen_report.json and mypen_report.html

Any of the above can be skipped: --no-sqli (or --no-getgresql /
--no-postgresql individually), --no-ports, --no-jslibs, --no-csrf,
--no-crawl, --no-xss, --no-open-redirect, --no-http-methods,
--no-subdomains, --no-json, --no-html. --port-range and --json/--html PATH
override the port list / output paths.

All detection (SQLi, XSS, open redirect, exposed paths, outdated libs) is
a SIGNAL to check manually, not a confirmed vulnerability — this tool does
not exploit or extract data.

This sends a LOT of requests by default (crawl x sqli/xss tests x ports).
Only run it against sites you own or have written permission to test, and
raise --delay if you're on a small or shared host.

Usage:
    pip install requests beautifulsoup4
    python mypen.py https://example.com --i-own-this
    python mypen.py https://example.com --i-own-this --no-ports --no-sqli
    python mypen.py https://example.com --i-own-this --json out.json --html out.html
"""
import argparse
import csv
import hashlib
import html
import os
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import re
import secrets
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse, urljoin

from bs4 import BeautifulSoup

import requests

TIMEOUT = 10
UA = "MyPEN/1.0 (authorized website security audit)"
DB_PATH = "mypen_history.sqlite3"

def human_duration(seconds):
    """Format a rough duration estimate like '~8s' or '~2m 15s'."""
    seconds = max(1, round(seconds))
    if seconds < 60:
        return f"~{seconds}s"
    m, s = divmod(seconds, 60)
    return f"~{m}m {s}s" if s else f"~{m}m"


def confirm_step(label, skip_prompts, note=None, eta_seconds=None):
    """Ask y/n right before one specific check starts. Returns True to run it."""
    if skip_prompts:
        return True
    print(f"\n[?] Next up: {label}")
    if eta_seconds is not None:
        print(f"    Estimated time: {human_duration(eta_seconds)} (rough estimate, "
              "varies with site structure and network conditions)")
    if note:
        print(f"    {note}")
    while True:
        answer = input("    Run this step? [y/N]: ").strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("", "n", "no"):
            print("    Skipped.")
            return False
        print("    Please answer y or n.")


BANNER = r"""
 __  __       ____  _____ _   _ 
|  \/  |_   _|  _ \| ____| \ | |
| |\/| | | | | |_) |  _| |  \| |
| |  | | |_| |  __/| |___| |\  |
|_|  |_|\__, |_|   |_____|_| \_|
        |___/                  
  Website self-scan oh yeah   
"""

SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
findings = []


def add(sev, title, detail=""):
    findings.append((sev, title, detail))


# --------------------------------------------------------------- headers
SECURITY_HEADERS = {
    "Strict-Transport-Security": ("MEDIUM", "HSTS missing: browsers may use plain HTTP."),
    "Content-Security-Policy": ("MEDIUM", "No CSP: weaker protection against XSS."),
    "X-Content-Type-Options": ("LOW", "Should be 'nosniff'."),
    "Referrer-Policy": ("LOW", "Referrer info may leak to other sites."),
    "X-Frame-Options": ("LOW", "Clickjacking risk (or use CSP frame-ancestors)."),
}


def check_headers(resp):
    for name, (sev, why) in SECURITY_HEADERS.items():
        if name == "X-Frame-Options" and "frame-ancestors" in resp.headers.get(
            "Content-Security-Policy", ""
        ):
            continue
        if name not in resp.headers:
            add(sev, f"Missing header: {name}", why)

    for name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
        val = resp.headers.get(name)
        if val and any(ch.isdigit() for ch in val):
            add("LOW", f"Version disclosure in {name}", val)


# --------------------------------------------------------------- cookies
def check_cookies(resp, is_https):
    try:
        raw = resp.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        raw = []
    for c in raw:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        if is_https and "secure" not in low:
            add("MEDIUM", f"Cookie '{name}' missing Secure flag")
        if "httponly" not in low:
            add("LOW", f"Cookie '{name}' missing HttpOnly flag",
                "Fine for cookies JS must read; bad for session cookies.")
        if "samesite" not in low:
            add("LOW", f"Cookie '{name}' missing SameSite attribute")


# ------------------------------------------------------------------- TLS
def check_tls(host, port):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                version = s.version()
        expires = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc
        )
        days = (expires - datetime.now(timezone.utc)).days
        if days < 0:
            add("HIGH", "TLS certificate expired", f"Expired {-days} days ago")
        elif days < 21:
            add("MEDIUM", "TLS certificate expires soon", f"{days} days left")
        else:
            add("INFO", "TLS certificate valid", f"{days} days left")
        if version in ("TLSv1", "TLSv1.1"):
            add("HIGH", "Outdated TLS version negotiated", version)
        else:
            add("INFO", "TLS version", version)
    except ssl.SSLCertVerificationError as e:
        add("HIGH", "TLS certificate failed verification", str(e))
    except (OSError, ssl.SSLError) as e:
        add("MEDIUM", "Could not complete TLS check", str(e))


def check_http_redirect(host):
    try:
        r = requests.get(f"http://{host}/", timeout=TIMEOUT, allow_redirects=False,
                         headers={"User-Agent": UA})
        loc = r.headers.get("Location", "")
        if not (300 <= r.status_code < 400 and loc.startswith("https://")):
            add("MEDIUM", "HTTP does not redirect to HTTPS",
                f"Status {r.status_code}")
    except requests.RequestException:
        add("INFO", "Port 80 not reachable (may be fine)")


# ------------------------------------------------------------------ CORS
def check_cors(url):
    evil = "https://evil.example"
    try:
        r = requests.get(url, timeout=TIMEOUT, allow_redirects=False,
                         headers={"User-Agent": UA, "Origin": evil})
    except requests.RequestException:
        return
    acao = r.headers.get("Access-Control-Allow-Origin")
    creds = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
    if acao == evil and creds:
        add("HIGH", "CORS reflects arbitrary Origin with credentials")
    elif acao == evil:
        add("MEDIUM", "CORS reflects arbitrary Origin")
    elif acao == "*":
        add("LOW", "CORS allows any origin (*)", "OK for public APIs only.")


# ---------------------------------------------------------- exposed files
# path -> (severity, substring that confirms it's real, or None)
SENSITIVE_PATHS = {
    "/.git/HEAD": ("HIGH", "ref:"),
    "/.env": ("HIGH", "="),
    "/.DS_Store": ("MEDIUM", None),
    "/backup.zip": ("HIGH", None),
    "/backup.sql": ("HIGH", None),
    "/db.sql": ("HIGH", None),
    "/phpinfo.php": ("MEDIUM", "phpinfo"),
    "/server-status": ("MEDIUM", "Apache"),
    "/wp-config.php.bak": ("HIGH", None),
    "/config.json": ("LOW", None),
    "/admin": ("INFO", None),
    "/login": ("INFO", None),
    "/robots.txt": ("INFO", "Disallow"),
}


def check_exposed(base, delay):
    # Learn what a "not found" page looks like, to avoid false positives
    # on sites that return 200 for everything (single-page apps).
    junk = f"/{secrets.token_hex(8)}"
    try:
        b = requests.get(base + junk, timeout=TIMEOUT, headers={"User-Agent": UA})
        soft404_len = len(b.content) if b.status_code == 200 else None
    except requests.RequestException:
        soft404_len = None

    for path, (sev, marker) in SENSITIVE_PATHS.items():
        time.sleep(delay)
        try:
            r = requests.get(base + path, timeout=TIMEOUT, allow_redirects=False,
                             headers={"User-Agent": UA})
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        if soft404_len is not None and abs(len(r.content) - soft404_len) < 50:
            continue  # looks like the catch-all page
        if marker and marker not in r.text[:5000]:
            continue
        add(sev, f"Reachable: {path}", f"HTTP 200, {len(r.content)} bytes")


# ------------------------------------------------------------- port scan
# Plain TCP connect scan (like `nmap -sT`) — no raw sockets, no stealth
# tricks, just "can I open a connection". Only scan hosts you own/control;
# scanning third-party IPs without permission can violate their ToS or
# the law even when it's this simple.

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP (submission)",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3000: "dev server (node/etc.)", 3306: "MySQL", 3389: "RDP",
    5000: "dev server (flask/etc.)", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8000: "HTTP-alt", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    9200: "Elasticsearch", 27017: "MongoDB",
}

RISKY_IF_PUBLIC = {21, 22, 23, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017}


def _probe_port(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def check_ports(host, ports, timeout=1.5, workers=20):
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_probe_port, host, port, timeout): port for port in ports}
        for fut in as_completed(futures):
            port = futures[fut]
            if fut.result():
                open_ports.append(port)

    for port in sorted(open_ports):
        name = COMMON_PORTS.get(port, "unknown service")
        if port in RISKY_IF_PUBLIC:
            add("MEDIUM", f"Port {port} ({name}) is open",
                "Often shouldn't be exposed to the internet directly — "
                "consider a firewall rule or VPN/bastion access.")
        elif port in (80, 443, 8080, 8443):
            add("INFO", f"Port {port} ({name}) is open")
        else:
            add("LOW", f"Port {port} ({name}) is open", "Confirm this is intended.")

    if not open_ports:
        add("INFO", "Port scan found no open ports in the scanned list")


# ---------------------------------------------------------------- SQLi
# DETECTION ONLY. This does not extract data. If something fires here,
# confirm manually or with sqlmap before you consider it proven, and only
# against a site you own / have written permission to test.

DB_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning: mysqli?",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"postgresql.*error",
    r"sqlstate\[",
    r"sqlite3?\.operationalerror",
    r"ora-\d{5}",
    r"microsoft odbc .* sql server",
    r"unterminated string literal",
    r"syntax error at or near",
]
ERROR_RE = re.compile("|".join(DB_ERROR_SIGNATURES), re.IGNORECASE)

TIME_PAYLOADS = {
    # generic 5-second delay per backend; appended to existing param value
    "mysql": "' AND SLEEP(5)-- -",
    "postgres": "'; SELECT pg_sleep(5)-- -",
    "mssql": "'; WAITFOR DELAY '0:0:5'-- -",
}
TIME_THRESHOLD = 4.5  # seconds of extra delay counted as a hit


def _get(url, params=None, data=None, method="GET"):
    try:
        if method == "GET":
            return requests.get(url, params=params, timeout=TIMEOUT + 10, allow_redirects=False,
                                headers={"User-Agent": UA})
        return requests.post(url, data=data, timeout=TIMEOUT + 10,
                             headers={"User-Agent": UA})
    except requests.RequestException:
        return None


def _test_param_set(base_url, method, fixed, param, baseline_text, delay):
    """Test one parameter for error-based, boolean-based, and time-based SQLi."""
    hits = []

    # --- error-based ---
    probe = dict(fixed)
    probe[param] = fixed.get(param, "") + "'"
    time.sleep(delay)
    r = _get(base_url, params=probe if method == "GET" else None,
             data=probe if method == "POST" else None, method=method)
    if r is not None and ERROR_RE.search(r.text):
        hits.append(("HIGH", "error-based", None))

    # --- boolean-based ---
    true_p = dict(fixed); true_p[param] = fixed.get(param, "") + "' OR '1'='1"
    false_p = dict(fixed); false_p[param] = fixed.get(param, "") + "' OR '1'='2"
    time.sleep(delay)
    rt = _get(base_url, params=true_p if method == "GET" else None,
              data=true_p if method == "POST" else None, method=method)
    time.sleep(delay)
    rf = _get(base_url, params=false_p if method == "GET" else None,
              data=false_p if method == "POST" else None, method=method)
    if rt is not None and rf is not None:
        if rt.status_code != rf.status_code or len(rt.text) != len(rf.text):
            hits.append(("HIGH", "boolean-based (true/false responses differ)", None))

    # --- time-based blind (slower, only if nothing found yet) ---
    if not hits:
        for dbname, payload in TIME_PAYLOADS.items():
            probe = dict(fixed)
            probe[param] = fixed.get(param, "") + payload
            time.sleep(delay)
            start = time.time()
            r = _get(base_url, params=probe if method == "GET" else None,
                     data=probe if method == "POST" else None, method=method)
            elapsed = time.time() - start
            if r is not None and elapsed >= TIME_THRESHOLD:
                hits.append(("HIGH", f"time-based blind ({dbname}-style payload, "
                                      f"{elapsed:.1f}s delay)", None))
                break  # one confirmation is enough, don't hammer further

    return hits


def _sqli_forms_by_method(url, delay, method_filter, max_forms=5):
    """Shared engine for both GETgreSQL and POSTgreSQL form testing."""
    r = _get(url, method="GET")
    if r is None:
        return
    soup = BeautifulSoup(r.text, "html.parser")
    forms = soup.find_all("form")[:max_forms]
    p = urlparse(url)

    for form in forms:
        method = (form.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            method = "GET"
        if method != method_filter:
            continue

        action = form.get("action") or url
        target = action if action.startswith("http") else \
            urljoin(url, action)
        if not _same_origin_url(target, url):
            add("INFO", "Skipped out-of-scope form", f"Form action is outside the exact scanned origin: {target}")
            continue

        fixed = {}
        for inp in form.find_all(["input", "textarea"]):
            name = inp.get("name")
            if not name:
                continue
            fixed[name] = inp.get("value") or "test"
        if not fixed:
            continue

        for param in list(fixed):
            for sev, kind, _ in _test_param_set(target, method, fixed, param, None, delay):
                add(sev, f"Possible SQL injection in form field '{param}'",
                    f"{kind} — form at {target} ({method})")


def check_getgresql(url, delay, max_forms=5):
    """GETgreSQL: SQLi testing of URL query-string params and GET-method forms."""
    p = urlparse(url)
    qs = dict(parse_qsl(p.query))
    if qs:
        base = urlunparse((p.scheme, p.netloc, p.path, "", "", ""))
        for param in qs:
            for sev, kind, _ in _test_param_set(base, "GET", qs, param, None, delay):
                add(sev, f"Possible SQL injection in URL parameter '{param}'", kind)

    _sqli_forms_by_method(url, delay, "GET", max_forms)


def check_postgresql(url, delay, max_forms=5):
    """POSTgreSQL: SQLi testing of POST-method form fields."""
    _sqli_forms_by_method(url, delay, "POST", max_forms)


# ----------------------------------------------------------------- crawl
def crawl(start_url, max_pages, delay):
    """Breadth-first, same-origin crawl. Returns a list of page URLs."""
    start = urlparse(start_url)
    origin = (start.scheme, start.netloc)
    seen = {start_url}
    queue = [start_url]
    pages = []

    while queue and len(pages) < max_pages:
        url = queue.pop(0)
        r = _get(url, method="GET")
        if r is None or "text/html" not in r.headers.get("Content-Type", ""):
            continue
        pages.append(url)

        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"]).split("#")[0]
            lp = urlparse(link)
            if (lp.scheme, lp.netloc) != origin or link in seen:
                continue
            seen.add(link)
            queue.append(link)

        time.sleep(delay)

    return pages


# --------------------------------------------------------- JS libraries
# Minimum versions below which there are widely-known public CVEs. Not
# exhaustive — treat a hit as "worth checking", not a confirmed finding.
JS_LIB_MIN_VERSIONS = {
    "jquery": (3, 5, 0),
    "bootstrap": (4, 3, 1),
    "angular": (1, 8, 0),
    "lodash": (4, 17, 21),
    "moment": (2, 29, 4),
    "handlebars": (4, 7, 7),
    "vue": (2, 7, 0),
}
JS_LIB_RE = re.compile(
    r"(jquery|bootstrap|angular|lodash|moment|handlebars|vue)"
    r"[.\-]*(?:min\.)?(?:js)?[\-@/]?v?(\d+\.\d+\.\d+)",
    re.IGNORECASE,
)


def check_js_libraries(pages):
    found = {}  # lib -> (version_tuple, source_url)
    for url in pages:
        r = _get(url, method="GET")
        if r is None:
            continue
        soup = BeautifulSoup(r.text, "html.parser")
        for script in soup.find_all("script", src=True):
            src = script["src"]
            m = JS_LIB_RE.search(src)
            if not m:
                continue
            lib = m.group(1).lower()
            try:
                ver = tuple(int(x) for x in m.group(2).split("."))
            except ValueError:
                continue
            if lib not in found or ver < found[lib][0]:
                found[lib] = (ver, src)

    for lib, (ver, src) in found.items():
        ver_str = ".".join(str(x) for x in ver)
        min_ver = JS_LIB_MIN_VERSIONS.get(lib)
        if min_ver and ver < min_ver:
            min_str = ".".join(str(x) for x in min_ver)
            add("MEDIUM", f"Outdated {lib} ({ver_str})",
                f"Below {min_str} — check for known CVEs. Source: {src}")
        else:
            add("INFO", f"Detected {lib} {ver_str}", src)


# ------------------------------------------------------------------ CSRF
CSRF_FIELD_HINTS = ("csrf", "token", "authenticity_token", "__requestverificationtoken")


def check_csrf_forms(pages):
    seen_forms = set()
    for url in pages:
        r = _get(url, method="GET")
        if r is None:
            continue
        soup = BeautifulSoup(r.text, "html.parser")
        p = urlparse(url)
        for form in soup.find_all("form"):
            method = (form.get("method") or "GET").upper()
            if method != "POST":
                continue  # CSRF tokens matter for state-changing (POST) forms

            action = form.get("action") or url
            target = action if action.startswith("http") else \
                urljoin(url, action)
            if not _same_origin_url(target, url):
                add("INFO", "Skipped out-of-scope form", f"Form action is outside the exact scanned origin: {target}")
                continue
            key = (target, method)
            if key in seen_forms:
                continue
            seen_forms.add(key)

            names = [(inp.get("name") or "").lower() for inp in form.find_all("input")]
            has_token = any(h in n for n in names for h in CSRF_FIELD_HINTS)
            if not has_token:
                add("MEDIUM", "POST form may be missing CSRF protection",
                    f"Form at {target} — no field named like csrf/token found. "
                    "Note: header- or cookie-based CSRF protection won't show up here, "
                    "so confirm manually before treating this as a real gap.")


# ------------------------------------------------------------------ XSS
# Reflected XSS detection only: a unique marker is sent in, and we check
# whether it comes back UNESCAPED in the HTML response. This is a signal,
# not proof — confirm manually (e.g. does it actually execute in a browser)
# before treating it as a real finding.

def _xss_marker():
    return "xss" + secrets.token_hex(4)


def _reflects_unescaped(text, marker):
    payload = f"<svg/onload=alert('{marker}')>"
    if payload in text:
        return True
    # also catch cases where the payload lands inside an existing tag/attr
    # unescaped, which is still a sign input isn't being HTML-encoded
    if f"onload=alert('{marker}')" in text and "&lt;svg" not in text:
        return True
    return False


def _test_param_xss(base_url, method, fixed, param, delay):
    marker = _xss_marker()
    payload = f"<svg/onload=alert('{marker}')>"
    probe = dict(fixed)
    probe[param] = payload
    time.sleep(delay)
    r = _get(base_url, params=probe if method == "GET" else None,
             data=probe if method == "POST" else None, method=method)
    if r is not None and _reflects_unescaped(r.text, marker):
        return True
    return False


def check_xss_url_params(url, delay):
    p = urlparse(url)
    qs = dict(parse_qsl(p.query))
    if not qs:
        return
    base = urlunparse((p.scheme, p.netloc, p.path, "", "", ""))
    for param in qs:
        if _test_param_xss(base, "GET", qs, param, delay):
            add("HIGH", f"Possible reflected XSS in URL parameter '{param}'",
                "Input came back unescaped in the response — confirm in a browser.")


def check_xss_forms(url, delay, max_forms=5):
    r = _get(url, method="GET")
    if r is None:
        return
    soup = BeautifulSoup(r.text, "html.parser")
    forms = soup.find_all("form")[:max_forms]
    p = urlparse(url)

    for form in forms:
        action = form.get("action") or url
        method = (form.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            method = "GET"
        target = action if action.startswith("http") else \
            urljoin(url, action)
        if not _same_origin_url(target, url):
            add("INFO", "Skipped out-of-scope form", f"Form action is outside the exact scanned origin: {target}")
            continue

        fixed = {}
        for inp in form.find_all(["input", "textarea"]):
            name = inp.get("name")
            if not name:
                continue
            fixed[name] = inp.get("value") or "test"
        if not fixed:
            continue

        for param in list(fixed):
            if _test_param_xss(target, method, fixed, param, delay):
                add("HIGH", f"Possible reflected XSS in form field '{param}'",
                    f"Input came back unescaped — form at {target} ({method}). "
                    "Confirm in a browser.")


# --------------------------------------------------------- open redirect
REDIRECT_PARAM_HINTS = ("url", "redirect", "redirect_uri", "return", "returnurl",
                         "return_to", "next", "dest", "destination", "continue", "r")


def check_open_redirect(url, delay):
    p = urlparse(url)
    qs = dict(parse_qsl(p.query))
    if not qs:
        return
    base = urlunparse((p.scheme, p.netloc, p.path, "", "", ""))
    evil = "https://evil.example"

    for param in qs:
        if not any(h in param.lower() for h in REDIRECT_PARAM_HINTS):
            continue
        probe = dict(qs)
        probe[param] = evil
        time.sleep(delay)
        try:
            r = requests.get(base, params=probe, timeout=TIMEOUT,
                             allow_redirects=False, headers={"User-Agent": UA})
        except requests.RequestException:
            continue
        loc = r.headers.get("Location", "")
        if 300 <= r.status_code < 400 and loc.startswith(evil):
            add("MEDIUM", f"Possible open redirect via parameter '{param}'",
                f"Setting it to {evil} produced a redirect there (HTTP {r.status_code}).")


# ------------------------------------------------------------- HTTP methods
RISKY_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT"}


def check_http_methods(url):
    try:
        r = requests.options(url, timeout=TIMEOUT, headers={"User-Agent": UA})
    except requests.RequestException:
        return
    allow = r.headers.get("Allow", "")
    if not allow:
        return
    methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
    risky = methods & RISKY_METHODS
    if risky:
        add("MEDIUM", f"Potentially risky HTTP methods enabled: {', '.join(sorted(risky))}",
            f"Server reports Allow: {allow}. Confirm these are actually needed "
            "and properly access-controlled.")
    if "TRACE" in methods:
        add("LOW", "TRACE method enabled",
            "Can sometimes be used for cross-site tracing (XST) attacks; usually safe to disable.")


# --------------------------------------------------------- subdomain enum
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "autodiscover",
    "cpanel", "whm", "admin", "api", "dev", "staging", "test", "beta", "demo",
    "portal", "vpn", "remote", "app", "blog", "shop", "store", "support",
    "help", "docs", "status", "cdn", "static", "assets", "img", "images",
    "secure", "login", "dashboard", "panel", "git", "jenkins", "ci", "db",
    "mysql", "sql", "backup", "old", "new", "m", "mobile",
]


def _resolves(host):
    try:
        socket.gethostbyname(host)
        return True
    except socket.gaierror:
        return False


def check_subdomains(domain, workers=20):
    found = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_resolves, f"{sub}.{domain}"): sub for sub in COMMON_SUBDOMAINS}
        for fut in as_completed(futures):
            sub = futures[fut]
            if fut.result():
                found.append(f"{sub}.{domain}")

    for host in sorted(found):
        add("INFO", f"Subdomain found: {host}",
            "Resolves — not itself a vulnerability, but worth knowing it exists "
            "and is reachable; consider scanning it separately if it's yours.")

    if not found:
        add("INFO", "Subdomain enumeration found nothing",
            f"No common subdomains resolved for {domain} (wordlist of "
            f"{len(COMMON_SUBDOMAINS)} names).")


# -------------------------------------------------------------- reporting
def write_json_report(path, scanned_url):
    data = {
        "url": scanned_url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "findings": [
            {"severity": sev, "title": title, "detail": detail}
            for sev, title, detail in findings
        ],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


SEV_COLOR = {
    "HIGH": "#c0392b",
    "MEDIUM": "#d68910",
    "LOW": "#2471a3",
    "INFO": "#7f8c8d",
}


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def write_html_report(path, scanned_url):
    counts = {s: sum(1 for f in findings if f[0] == s) for s in SEV_ORDER}
    ordered = sorted(findings, key=lambda f: SEV_ORDER[f[0]])

    summary_chips = "".join(
        f'<span class="chip" style="background:{SEV_COLOR[s]}">{s}: {n}</span>'
        for s, n in counts.items()
    )

    rows = "".join(
        f'<tr class="row-{sev.lower()}">'
        f'<td><span class="badge" style="background:{SEV_COLOR[sev]}">{sev}</span></td>'
        f'<td>{_esc(title)}</td>'
        f'<td>{_esc(detail) if detail else ""}</td>'
        f'</tr>'
        for sev, title, detail in ordered
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>MyPEN report — {_esc(scanned_url)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif;
         background: #f5f6f8; color: #222; margin: 0; padding: 2rem; }}
  .wrap {{ max-width: 900px; margin: 0 auto; }}
  h1 {{ font-size: 1.4rem; margin-bottom: 0.2rem; word-break: break-all; }}
  .meta {{ color: #666; font-size: 0.9rem; margin-bottom: 1.2rem; }}
  .chip {{ display: inline-block; color: #fff; border-radius: 4px;
          padding: 0.25rem 0.6rem; margin-right: 0.5rem; font-size: 0.85rem; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff;
          box-shadow: 0 1px 3px rgba(0,0,0,0.08); margin-top: 1.2rem; }}
  th, td {{ text-align: left; padding: 0.6rem 0.8rem; border-bottom: 1px solid #eee;
           vertical-align: top; font-size: 0.92rem; }}
  th {{ background: #fafafa; }}
  .badge {{ color: #fff; border-radius: 4px; padding: 0.15rem 0.5rem;
           font-size: 0.78rem; font-weight: 600; white-space: nowrap; }}
  .row-high {{ background: #fdf1f0; }}
  .disclaimer {{ margin-top: 1.5rem; font-size: 0.82rem; color: #888; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>MyPEN report</h1>
  <div class="meta">
    {_esc(scanned_url)}<br>
    Generated {_esc(datetime.now(timezone.utc).isoformat())}
  </div>
  <div>{summary_chips}</div>
  <table>
    <thead><tr><th>Severity</th><th>Finding</th><th>Detail</th></tr></thead>
    <tbody>
      {rows if rows else '<tr><td colspan="3">No findings.</td></tr>'}
    </tbody>
  </table>
  <div class="disclaimer">
    Automated results — confirm findings manually before acting on them.
    Only scan sites you own or have written permission to test.
  </div>
</div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


# ------------------------------------------------------ upgraded features

def _same_origin_url(candidate, origin_url):
    """True only for HTTP(S) URLs on the exact same scheme/host/port."""
    try:
        c, o = urlparse(candidate), urlparse(origin_url)
        def port(p): return p.port or (443 if p.scheme == "https" else 80)
        return (c.scheme in ("http", "https") and c.scheme == o.scheme and
                (c.hostname or "").lower() == (o.hostname or "").lower() and port(c) == port(o))
    except ValueError:
        return False


def check_advanced(url, delay=0.2):
    """Low-impact DNS/metadata checks; no brute force or exploit payloads."""
    p = urlparse(url)
    host = p.hostname
    base = f"{p.scheme}://{p.netloc}"
    # DNS resolution
    try:
        addresses = sorted({x[4][0] for x in socket.getaddrinfo(host, None)})
        add("INFO", "DNS addresses", ", ".join(addresses))
    except OSError as exc:
        add("LOW", "DNS resolution failed", str(exc))
    # Email DNS posture; dnspython is optional
    try:
        import dns.resolver
        domain = host[4:] if host.startswith("www.") else host
        for record in ("TXT", "MX"):
            try:
                answers = dns.resolver.resolve(domain, record, lifetime=3)
                vals = [str(a) for a in answers]
                if record == "TXT":
                    txt = " ".join(vals)
                    if not any(x in txt.lower() for x in ("v=spf1", "v=dmarc1")):
                        add("INFO", f"DNS {record} records", "TXT exists; no SPF/DMARC marker found in returned TXT records.")
                    else:
                        add("INFO", f"DNS {record} records", txt[:500])
                else:
                    add("INFO", "DNS MX records", ", ".join(vals)[:500])
            except Exception:
                add("LOW" if record == "MX" else "MEDIUM", f"No readable DNS {record} record", f"Could not retrieve {record}; verify with your DNS provider.")
    except ImportError:
        add("INFO", "Email DNS checks skipped", "Install dnspython to enable SPF/DMARC/MX checks: pip install dnspython")
    # Well-known metadata endpoints and mixed-content inspection
    for path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
        try:
            r = requests.get(base + path, timeout=TIMEOUT, allow_redirects=False, headers={"User-Agent": UA})
            if r.status_code == 200:
                if path == "/.well-known/security.txt":
                    if "contact:" not in r.text.lower():
                        add("LOW", "security.txt may be incomplete", "Reachable file does not contain a Contact field.")
                    else:
                        add("INFO", "security.txt found", "A security contact file is published.")
                elif path == "/sitemap.xml":
                    add("INFO", "Sitemap found", f"HTTP 200; {len(r.content)} bytes")
                else:
                    add("INFO", "robots.txt found", f"HTTP 200; {len(r.content)} bytes. Entries are public hints, not access controls.")
            elif path == "/.well-known/security.txt" and r.status_code == 404:
                add("LOW", "security.txt not found", "Consider publishing a contact at /.well-known/security.txt")
        except requests.RequestException:
            pass
        time.sleep(max(0, delay))
    try:
        r = requests.get(url, timeout=TIMEOUT, allow_redirects=False, headers={"User-Agent": UA})
        if "text/html" in r.headers.get("Content-Type", ""):
            soup = BeautifulSoup(r.text, "html.parser")
            mixed = []
            for tag, attr in (("script", "src"), ("img", "src"), ("iframe", "src"), ("link", "href")):
                for node in soup.find_all(tag):
                    value = node.get(attr, "").strip()
                    if value.startswith("http://"):
                        mixed.append(value)
            if mixed:
                add("MEDIUM", "Potential mixed content", f"Found {len(mixed)} HTTP resource(s); examples: {', '.join(mixed[:5])}")
    except requests.RequestException:
        pass


def write_csv_report(path, scanned_url):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "scanned_at", "severity", "title", "detail"])
        stamp = datetime.now(timezone.utc).isoformat()
        for sev, title, detail in sorted(findings, key=lambda x: SEV_ORDER[x[0]]):
            writer.writerow([scanned_url, stamp, sev, title, detail])


def write_pdf_report(path, scanned_url):
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter, landscape
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet
    except ImportError:
        raise RuntimeError("PDF export needs reportlab. Install it with: pip install reportlab")
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(path, pagesize=landscape(letter), title="MyPEN Security Report")
    counts = {sev: sum(1 for f in findings if f[0] == sev) for sev in SEV_ORDER}
    story = [Paragraph("MyPEN Security Report", styles["Title"]), Paragraph(html.escape(scanned_url), styles["Normal"]),
             Paragraph("Generated " + datetime.now(timezone.utc).isoformat(), styles["Normal"]),
             Paragraph("Counts: " + " | ".join(f"{k}: {v}" for k, v in counts.items()), styles["Normal"]), Spacer(1, 12)]
    rows = [["Severity", "Finding", "Detail"]]
    for sev, title, detail in sorted(findings, key=lambda x: SEV_ORDER[x[0]]):
        rows.append([Paragraph(html.escape(sev), styles["BodyText"]), Paragraph(html.escape(title), styles["BodyText"]), Paragraph(html.escape(detail or ""), styles["BodyText"])])
    table = Table(rows, repeatRows=1, colWidths=[70, 220, 430])
    table.setStyle(TableStyle([("BACKGROUND", (0,0),(-1,0), colors.HexColor("#263746")), ("TEXTCOLOR",(0,0),(-1,0),colors.white), ("GRID",(0,0),(-1,-1),0.35,colors.grey), ("VALIGN",(0,0),(-1,-1),"TOP"), ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f2f5f7")])]))
    story.append(table)
    story.append(Spacer(1, 10))
    story.append(Paragraph("Automated findings are signals, not proof. Validate manually. Only scan systems you own or are authorized to test.", styles["Italic"]))
    doc.build(story)


def save_history(scanned_url, report_path=DB_PATH):
    counts = {sev: sum(1 for f in findings if f[0] == sev) for sev in SEV_ORDER}
    with sqlite3.connect(report_path) as db:
        db.execute("CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, scanned_at TEXT, url TEXT, counts_json TEXT, findings_json TEXT)")
        db.execute("INSERT INTO scans(scanned_at,url,counts_json,findings_json) VALUES(?,?,?,?)", (
            datetime.now(timezone.utc).isoformat(), scanned_url, json.dumps(counts),
            json.dumps([{"severity":s,"title":t,"detail":d} for s,t,d in findings])))


def show_history(limit=10, db_path=DB_PATH):
    if not os.path.exists(db_path):
        print("No scan history yet."); return
    with sqlite3.connect(db_path) as db:
        rows = db.execute("SELECT id, scanned_at, url, counts_json FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    if not rows:
        print("No scan history yet."); return
    print("\nRecent MyPEN scans")
    for ident, stamp, url, raw in rows:
        counts = json.loads(raw)
        print(f"#{ident} {stamp} | {url} | " + ", ".join(f"{k}={v}" for k,v in counts.items()))


def compare_baseline(path):
    try:
        old = json.loads(open(path, encoding="utf-8").read())
        old_keys = {(x.get("severity"), x.get("title"), x.get("detail", "")) for x in old.get("findings", [])}
        current = {(s,t,d) for s,t,d in findings}
        new = current - old_keys
        resolved = old_keys - current
        print(f"\nBaseline comparison: {len(new)} new, {len(resolved)} no longer detected")
        for s,t,d in sorted(new, key=lambda x: SEV_ORDER.get(x[0], 9)):
            print(f"  NEW [{s}] {t}" + (f" — {d}" if d else ""))
        for s,t,d in sorted(resolved, key=lambda x: SEV_ORDER.get(x[0], 9)):
            print(f"  CLEARED [{s}] {t}")
    except (OSError, ValueError, TypeError) as exc:
        print(f"[!] Could not compare baseline {path}: {exc}")


def run_local_api(host="127.0.0.1", port=8765, db_path=DB_PATH):
    """Read-only localhost API. Deliberately refuses non-loopback binding."""
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("For safety, MyPEN API can bind only to loopback (localhost).")
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path not in ("/", "/health", "/history"):
                self.send_error(404); return
            payload = {"app":"MyPEN", "status":"ok"}
            if self.path == "/history":
                if os.path.exists(db_path):
                    with sqlite3.connect(db_path) as db:
                        db.row_factory = sqlite3.Row
                        payload["scans"] = [dict(row) for row in db.execute("SELECT id,scanned_at,url,counts_json FROM scans ORDER BY id DESC LIMIT 100")]
                else: payload["scans"] = []
            body = json.dumps(payload, indent=2).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body))); self.send_header("Cache-Control", "no-store")
            self.end_headers(); self.wfile.write(body)
        def log_message(self, fmt, *args): print("[API] " + (fmt % args))
    server = HTTPServer((host, port), Handler)
    print(f"MyPEN read-only API listening at http://{host}:{port} (Ctrl+C to stop)")
    print("Endpoints: /health, /history")
    try: server.serve_forever()
    except KeyboardInterrupt: print("\nAPI stopped.")
    finally: server.server_close()


def terminal_summary(scanned_url):
    counts = {s: sum(1 for f in findings if f[0] == s) for s in SEV_ORDER}
    width = 58
    print("\n" + "=" * width)
    print(" MyPEN | SECURITY SCAN SUMMARY")
    print("=" * width)
    print(f" Target: {scanned_url}")
    print("  " + " | ".join(f"{s}: {counts[s]}" for s in SEV_ORDER))
    print("-" * width)
    for sev, title, detail in sorted(findings, key=lambda f: SEV_ORDER[f[0]]):
        print(f"[{sev:<6}] {title}")
        if detail: print("         " + detail.replace("\n", " ")[:300])
    print("=" * width)


# ------------------------------------------------------------------ main

def main():
    ap = argparse.ArgumentParser(description="MyPEN — security hygiene scanner for your own site")
    ap.add_argument("url", nargs="?", help="e.g. https://example.com")
    ap.add_argument("--profile", choices=("quick", "standard", "full"), default="standard", help="quick skips active payload checks and port scan; standard uses configured checks; full uses all defaults")
    ap.add_argument("--csv", type=str, default="mypen_report.csv", metavar="PATH", help="CSV report path")
    ap.add_argument("--no-csv", action="store_true", help="skip CSV report")
    ap.add_argument("--pdf", type=str, default=None, metavar="PATH", help="optional PDF report (requires reportlab)")
    ap.add_argument("--baseline", type=str, default=None, help="compare results with a prior MyPEN JSON report")
    ap.add_argument("--history", action="store_true", help="show recent scan history and exit")
    ap.add_argument("--history-db", default=DB_PATH, help="SQLite history database path")
    ap.add_argument("--api", action="store_true", help="serve read-only local history API and exit")
    ap.add_argument("--api-host", default="127.0.0.1", help="API bind address (loopback only)")
    ap.add_argument("--api-port", type=int, default=8765, help="API port")
    ap.add_argument("--advanced", action=argparse.BooleanOptionalAction, default=True, help="DNS, metadata and mixed-content checks")
    ap.add_argument("--workers", type=int, default=10, help="concurrent TCP checks (1-50)")
    ap.add_argument("--i-own-this", action="store_true", required=False,
                    help="confirm you own or have written permission to test this site")
    ap.add_argument("--delay", type=float, default=0.5,
                    help="seconds between requests (default 0.5)")
    # Every check below runs by default now. Use --no-<check> to skip one.
    ap.add_argument("--sqli", action=argparse.BooleanOptionalAction, default=None,
                    help="shorthand for --getgresql + --postgresql together "
                         "(both on by default; --no-sqli skips both)")
    ap.add_argument("--getgresql", action=argparse.BooleanOptionalAction, default=True,
                    help="SQLi testing of URL query params + GET-method forms "
                         "(detection only; on by default; --no-getgresql to skip)")
    ap.add_argument("--postgresql", action=argparse.BooleanOptionalAction, default=True,
                    help="SQLi testing of POST-method form fields "
                         "(detection only; on by default; --no-postgresql to skip)")
    ap.add_argument("--ports", action=argparse.BooleanOptionalAction, default=True,
                    help="TCP connect scan of common ports (on by default; "
                         "--no-ports to skip)")
    ap.add_argument("--port-range", type=str, default=None,
                    help="custom ports to scan instead of the common list, "
                         "e.g. '1-1024' or '22,80,443,8080'")
    ap.add_argument("--port-timeout", type=float, default=1.5,
                    help="per-port connect timeout in seconds (default 1.5)")
    ap.add_argument("--crawl", action=argparse.BooleanOptionalAction, default=True,
                    help="crawl same-origin pages first, so --sqli/--jslibs/--csrf "
                         "cover the whole site (on by default; --no-crawl for just "
                         "the one URL given)")
    ap.add_argument("--max-pages", type=int, default=20,
                    help="max pages to visit when crawling (default 20)")
    ap.add_argument("--jslibs", action=argparse.BooleanOptionalAction, default=True,
                    help="detect JS library versions and flag outdated ones "
                         "(on by default; --no-jslibs to skip)")
    ap.add_argument("--csrf", action=argparse.BooleanOptionalAction, default=True,
                    help="check POST forms for a CSRF token field "
                         "(on by default; --no-csrf to skip)")
    ap.add_argument("--xss", action=argparse.BooleanOptionalAction, default=True,
                    help="test URL params and forms for reflected XSS "
                         "(on by default; --no-xss to skip)")
    ap.add_argument("--open-redirect", action=argparse.BooleanOptionalAction, default=True,
                    help="test likely redirect parameters for open redirect "
                         "(on by default; --no-open-redirect to skip)")
    ap.add_argument("--http-methods", action=argparse.BooleanOptionalAction, default=True,
                    help="check for risky HTTP methods via OPTIONS "
                         "(on by default; --no-http-methods to skip)")
    ap.add_argument("--subdomains", action=argparse.BooleanOptionalAction, default=True,
                    help="enumerate common subdomains via DNS resolution "
                         "(on by default; --no-subdomains to skip)")
    ap.add_argument("--json", type=str, default="mypen_report.json", metavar="PATH",
                    help="JSON report path (default: mypen_report.json)")
    ap.add_argument("--no-json", action="store_true", help="skip the JSON report")
    ap.add_argument("--html", type=str, default="mypen_report.html", metavar="PATH",
                    help="HTML report path (default: mypen_report.html)")
    ap.add_argument("--no-html", action="store_true", help="skip the HTML report")
    ap.add_argument("-y", "--yes", action="store_true",
                    help="skip the y/n confirmation prompt before a long/heavy run "
                         "(useful for scripts/automation)")
    args = ap.parse_args()
    if args.history:
        show_history(db_path=args.history_db); return
    if args.api:
        run_local_api(args.api_host, args.api_port, args.history_db); return
    if not args.url:
        ap.error("url is required unless --history or --api is used")
    if not args.i_own_this:
        ap.error("active scanning requires --i-own-this to confirm authorization")
    if not 1 <= args.workers <= 50:
        ap.error("--workers must be between 1 and 50")
    if args.profile == "quick":
        args.getgresql = args.postgresql = args.xss = args.open_redirect = False
        args.ports = False
        args.max_pages = min(args.max_pages, 5)
        args.delay = max(args.delay, 0.2)
    elif args.profile == "full":
        args.getgresql = args.postgresql = args.xss = args.open_redirect = True
        args.ports = args.jslibs = args.csrf = args.http_methods = args.subdomains = args.advanced = True
    if args.delay < 0:
        ap.error("--delay must be non-negative")
    if args.port_timeout <= 0:
        ap.error("--port-timeout must be positive")

    # --sqli is shorthand: if explicitly passed, it overrides the two
    # specific flags; if not passed (None), --getgresql/--postgresql stand.
    if args.sqli is not None:
        args.getgresql = args.sqli
        args.postgresql = args.sqli

    url = args.url.rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        ap.error("URL must be a valid http(s) URL without embedded credentials")
    host = p.hostname
    is_https = p.scheme == "https"
    port = p.port or (443 if is_https else 80)

    print(BANNER)
    print(f"[*] Scanning {url}\n")
    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=False, headers={"User-Agent": UA})
    except requests.RequestException as e:
        sys.exit(f"[!] Could not reach site: {e}")

    check_headers(resp)
    check_cookies(resp, is_https)
    if is_https:
        check_tls(host, port)
        check_http_redirect(host)
    else:
        add("MEDIUM", "Site served over plain HTTP")
    check_cors(url)
    if args.advanced and confirm_step("advanced DNS/metadata checks", args.yes, eta_seconds=4):
        check_advanced(url, args.delay)
    check_exposed(f"{p.scheme}://{p.netloc}", args.delay)

    # Rough per-request time budget used for all estimates below: the delay
    # between requests plus a guess at round-trip latency.
    REQ_TIME = args.delay + 0.3

    pages = [url]
    if args.crawl and confirm_step(
        f"crawl (up to {args.max_pages} pages)", args.yes,
        eta_seconds=args.max_pages * REQ_TIME
    ):
        print(f"[*] Crawling (max {args.max_pages} pages)...")
        pages = crawl(url, args.max_pages, args.delay)
        print(f"[*] Found {len(pages)} page(s)")

    # Worst-case requests per tested field: error-based(1) + boolean(2) +
    # time-based blind, up to 3 tries, each with a real 5s DB sleep baked in.
    SQLI_REQS_PER_FIELD = 6
    SQLI_TIME_PAYLOAD_SECS = 5  # each time-based probe can itself take ~5s

    if args.getgresql and confirm_step(
        "GETgreSQL (URL params + GET forms)", args.yes,
        eta_seconds=len(pages) * 3 * SQLI_REQS_PER_FIELD *
                    (REQ_TIME + SQLI_TIME_PAYLOAD_SECS / SQLI_REQS_PER_FIELD)
    ):
        print("[*] Running GETgreSQL checks...")
        for page in pages:
            check_getgresql(page, args.delay)

    if args.postgresql and confirm_step(
        "POSTgreSQL (POST forms)", args.yes,
        eta_seconds=len(pages) * 2 * SQLI_REQS_PER_FIELD *
                    (REQ_TIME + SQLI_TIME_PAYLOAD_SECS / SQLI_REQS_PER_FIELD)
    ):
        print("[*] Running POSTgreSQL checks...")
        for page in pages:
            check_postgresql(page, args.delay)

    if args.jslibs and confirm_step(
        "JS library version check", args.yes,
        eta_seconds=len(pages) * REQ_TIME
    ):
        print("[*] Checking JS library versions...")
        check_js_libraries(pages)

    if args.csrf and confirm_step(
        "CSRF token check on POST forms", args.yes,
        eta_seconds=len(pages) * REQ_TIME
    ):
        print("[*] Checking POST forms for CSRF tokens...")
        check_csrf_forms(pages)

    if args.xss and confirm_step(
        "reflected XSS testing", args.yes,
        note="sends test payloads into URL params and form fields",
        eta_seconds=len(pages) * 3 * REQ_TIME
    ):
        print("[*] Running reflected XSS checks...")
        for page in pages:
            check_xss_url_params(page, args.delay)
            check_xss_forms(page, args.delay)

    if args.open_redirect and confirm_step(
        "open redirect check", args.yes,
        eta_seconds=len(pages) * REQ_TIME
    ):
        print("[*] Checking for open redirect...")
        for page in pages:
            check_open_redirect(page, args.delay)

    if args.http_methods and confirm_step(
        "HTTP methods check (OPTIONS)", args.yes, eta_seconds=1
    ):
        print("[*] Checking HTTP methods...")
        check_http_methods(url)

    if args.subdomains and confirm_step(
        "subdomain enumeration (DNS only)", args.yes,
        eta_seconds=(len(COMMON_SUBDOMAINS) / 20) * 2  # 20 workers, ~2s/batch
    ):
        print(f"[*] Enumerating common subdomains for {host}...")
        # strip a leading "www." so we enumerate the base domain
        base_domain = host[4:] if host.startswith("www.") else host
        check_subdomains(base_domain)

    if args.ports:
        if args.port_range:
            ports = set()
            for part in args.port_range.split(","):
                part = part.strip()
                if "-" in part:
                    lo, hi = part.split("-")
                    ports.update(range(int(lo), int(hi) + 1))
                elif part:
                    ports.add(int(part))
        else:
            ports = set(COMMON_PORTS)

        if any(port < 1 or port > 65535 for port in ports):
            ap.error("ports must be between 1 and 65535")
        if len(ports) > 4096:
            ap.error("custom port ranges are limited to 4096 ports per scan")
        # Bounded worker pool; estimate uses configured concurrency.
        port_eta = (len(ports) / args.workers) * args.port_timeout
        if confirm_step(
            f"port scan ({len(ports)} ports)", args.yes,
            note="TCP connect scan — can be loud/logged on the target",
            eta_seconds=port_eta
        ):
            print(f"[*] Scanning {len(ports)} port(s) on {host}...")
            check_ports(host, sorted(ports), timeout=args.port_timeout, workers=args.workers)

    findings.sort(key=lambda f: SEV_ORDER[f[0]])
    terminal_summary(url)

    if args.baseline:
        compare_baseline(args.baseline)
    if not args.no_json:
        write_json_report(args.json, url)
        print(f"[*] JSON report written to {args.json}")
    if not args.no_html:
        write_html_report(args.html, url)
        print(f"[*] HTML report written to {args.html}")
    if not args.no_csv:
        write_csv_report(args.csv, url)
        print(f"[*] CSV report written to {args.csv}")
    if args.pdf:
        try:
            write_pdf_report(args.pdf, url)
            print(f"[*] PDF report written to {args.pdf}")
        except RuntimeError as exc:
            print(f"[!] {exc}")
    try:
        save_history(url, args.history_db)
        print(f"[*] Scan saved to history database: {args.history_db}")
    except (OSError, sqlite3.Error) as exc:
        print(f"[!] Could not save scan history: {exc}")


if __name__ == "__main__":
    main()
