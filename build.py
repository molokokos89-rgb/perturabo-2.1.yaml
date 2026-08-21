import json
import urllib.request
import re
import os
import subprocess

EXTERNAL_REJECT_URLS = [
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt",
    "https://raw.githubusercontent.com/5kms/oisd-singbox/main/domain_suffix_reject.txt",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/russia/runetfreedom/sing-box/rule-set-geosite/geosite-adblock.srs",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/russia/runetfreedom/sing-box/rule-set-geosite/geosite-adblockplus.srs"
]

WHITELIST_EXACT = [
    "tiktok.com", "facebook.com", "rutube.ru", "youtube.com", "vk.com",
    "t.me", "telegram.org", "instagram.com"
]

WHITELIST_PATTERNS = [
    r"^([^.]+\.)*tiktok\.com$",
    r"^([^.]+\.)*facebook\.com$",
    r"^([^.]+\.)*rutube\.ru$",
    r"^([^.]+\.)*googlevideo\.com$"
]

ALLOWED_AD_SUBDOMAINS = [
    "analytics", "ads", "pixel", "metrics", "telemetry", "tracker",
    "://tiktokcdn.com", "bdtone.com", "mon.pangle.io"
]

def is_dangerous_block(domain):
    if domain in WHITELIST_EXACT:
        return True
    
    for pattern in WHITELIST_PATTERNS:
        if re.match(pattern, domain):
            if any(sub in domain for sub in ALLOWED_AD_SUBDOMAINS):
                return False
            return True
            
    return False

def clean_domain(line):
    line = line.strip().lower()
    if not line or line.startswith(("#", "!", ";")):
        return None
    
    line = re.sub(r'^(127\.0\.0\.1|0\.0\.0\.0)\s+', '', line)
    line = line.split("#")[0].strip()
    
    if line.startswith("||"):
        line = line[2:]
    if line.endswith("^"):
        line = line[:-1]
        
    line = line.replace("*.", "")
    
    if re.match(r'^[a-z0-9.-]+\.[a-z]{2,6}$', line):
        return line
    return None

def main():
    rejected_domains = set()
    
    for url in AD_SOURCES:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as response:
                for line in response.read().decode('utf-8', errors='ignore').splitlines():
                    domain = clean_domain(line)
                    if domain:
                        if not is_dangerous_block(domain):
                            rejected_domains.add(domain)
        except Exception:
            pass

    if os.path.exists("my_rules_proxy.json"):
        try:
            with open("my_rules_proxy.json", "r", encoding="utf-8") as f:
                proxy_data = json.load(f)
                for rule in proxy_data.get("rules", []):
                    for d in rule.get("domain_suffix", []):
                        rejected_domains.discard(d.lower().strip())
        except Exception:
            pass

    output_data = {
        "version": 1,
        "rules": [
            {
                "domain_suffix": sorted(list(rejected_domains))
            }
        ]
    }
    
    with open("reject_rules.json", "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    main()
