import sys
import re
import json
import base64
import socket
import urllib.request
import urllib.parse
import subprocess
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

PROXY_JSON = "my_rules_proxy.json"
URLS_FILE = "urls.txt"

def download_text(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.read().decode('utf-8', errors='ignore')
    except Exception:
        return ""

def load_existing_proxy_domains():
    domains = set()
    if os.path.exists(PROXY_JSON):
        try:
            with open(PROXY_JSON, "r", encoding="utf-8") as f:
                data = json.load(f)
                for rule in data.get("rules", []):
                    if "domain_suffix" in rule:
                        for d in rule["domain_suffix"]:
                            domains.add(d.lower().strip())
        except Exception:
            pass
    return domains

def clean_domain(line):
    line = line.strip().lower()
    if not line or line.startswith(("#", "!", ";", "//")):
        return None
    line = re.sub(r'^(127\.0\.0\.1|0\.0\.0\.0)\s+', '', line)
    if "#" in line:
        line = line.split("#")[0]
    line = line.strip()
    if line.startswith("||"):
        line = line[2:]
    if line.endswith("^"):
        line = line[:-1]
    line = line.replace("*.", "")
    if re.match(r'^[a-z0-9.-]+\.[a-z]{2,6}$', line):
        return line
    return None

def load_domains_from_urls():
    if not os.path.exists(URLS_FILE):
        return set()
    with open(URLS_FILE, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    
    all_extracted = set()
    for index, url in enumerate(urls):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as response:
                content = response.read()
                
                if url.endswith(".json"):
                    data = json.loads(content.decode('utf-8'))
                    if "payload" in data: 
                        for d in data["payload"]:
                            all_extracted.add(d)
                    if "rules" in data:
                        for rule in data["rules"]:
                            if "domain" in rule: 
                                for d in rule["domain"]: all_extracted.add(d)
                            if "domain_suffix" in rule: 
                                for d in rule["domain_suffix"]: all_extracted.add(d)
                                
                elif url.endswith(".txt") or "/raw" in url:
                    for line in content.decode('utf-8', errors='ignore').splitlines():
                        d = clean_domain(line)
                        if d:
                            all_extracted.add(d)
                            
                elif url.endswith(".srs"):
                    srs_file = f"temp_addon_{index}.srs"
                    json_file = f"temp_addon_{index}.json"
                    with open(srs_file, "wb") as out: 
                        out.write(content)
                    subprocess.run(["sing-box", "rule-set", "decompile", srs_file, "--output", json_file], check=True)
                    with open(json_file, "r", encoding="utf-8") as jf:
                        data = json.load(jf)
                    for rule in data.get("rules", []):
                        if "domain" in rule:
                            for d in rule["domain"]: all_extracted.add(d)
                        if "domain_suffix" in rule:
                            for d in rule["domain_suffix"]: all_extracted.add(d)
                    if os.path.exists(srs_file): os.remove(srs_file)
                    if os.path.exists(json_file): os.remove(json_file)
        except Exception:
            pass
    return all_extracted

def test_single_domain(domain):
    try:
        req = urllib.request.Request(f"https://{domain}", headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as res:
            html = res.read().decode('utf-8', errors='ignore').lower()
            if any(w in html for w in ["заблокирован", "роскомнадзор", "block", "deny"]):
                return domain, True
            return domain, False
    except Exception:
        return domain, True

def check_domains_availability(domains_set):
    blocked = []
    allowed = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(test_single_domain, d): d for d in domains_set}
        for future in as_completed(futures):
            domain, is_blocked = future.result()
            if is_blocked:
                blocked.append(domain)
            else:
                allowed.append(domain)
    return sorted(blocked), sorted(allowed)

def main():
    existing_proxies = load_existing_proxy_domains()
    raw_domains = load_domains_from_urls()
    
    vetted_domains = set()
    for d in raw_domains:
        d_clean = clean_domain(d)
        if d_clean and d_clean not in existing_proxies:
            if not any(d_clean.endswith(zone) for zone in [".ru", ".su", ".by", ".xn--p1ai"]):
                vetted_domains.add(d_clean)
                
    if not vetted_domains:
        return

    blocked_list, allowed_list = check_domains_availability(vetted_domains)
    
    with open("blocked.json", "w", encoding="utf-8") as f:
        json.dump({"version": 1, "rules": [{"domain_suffix": blocked_list}]}, f, indent=2, ensure_ascii=False)
        
    with open("allowed.json", "w", encoding="utf-8") as f:
        json.dump({"version": 1, "rules": [{"domain_suffix": allowed_list}]}, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    main()
