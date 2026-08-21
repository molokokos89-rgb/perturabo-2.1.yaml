import urllib.request
import json
import os
import re

RKN_SOURCE = "https://githubusercontent.com"
PROXY_JSON = "my_rules_proxy.json"
OUTPUT_DIR = "rkn_splits"
MAX_DOMAINS_PER_FILE = 50000

def download_text(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=30) as response:
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

def main():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    existing_proxies = load_existing_proxy_domains()
    rkn_domains = set()
    
    csv_content = download_text(RKN_SOURCE)
    if not csv_content:
        return

    domain_pattern = re.compile(r'^[a-z0-9.-]+\.[a-z]{2,6}$')

    for line in csv_content.splitlines():
        parts = line.split(';')
        if len(parts) >= 2:
            raw_domains = parts.split(',')
            for rd in raw_domains:
                rd = rd.strip().lower().replace("*.", "")
                if rd and domain_pattern.match(rd):
                    if rd not in existing_proxies:
                        if not any(rd.endswith(zone) for zone in [".ru", ".su", ".by", ".xn--p1ai"]):
                            rkn_domains.add(rd)

    sorted_rkn = sorted(list(rkn_domains))
    total_domains = len(sorted_rkn)
    
    file_index = 1
    for i in range(0, total_domains, MAX_DOMAINS_PER_FILE):
        chunk = sorted_rkn[i:i + MAX_DOMAINS_PER_FILE]
        output_data = {
            "version": 1,
            "rules": [{"domain_suffix": chunk}]
        }
        
        file_name = os.path.join(OUTPUT_DIR, f"rkn_part{file_index}.json")
        with open(file_name, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        file_index += 1

if __name__ == "__main__":
    main()
