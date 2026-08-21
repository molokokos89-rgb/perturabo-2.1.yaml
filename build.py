import urllib.request
import re
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

RUS_JSON = "My_rules_RUS.json"
REJECT_JSON = "reject_rules.json"
PROXY_JSON = "my_rules_proxy.json"

DROPBOX_URL = "https://www.dropbox.com/scl/fi/759t1a2us3y0kblgat0xr/log-for-reject.txt?rlkey=zr2uqv81lx89rdl6q55geyucy&st=8lc13ygu&dl=1"

MAIN_REPO_RULES = {
    "rus": "https://raw.githubusercontent.com/molokokos89-rgb/perturabo-2.0.yaml/refs/heads/main/My_rules_RUS.json",
    "proxy": "https://raw.githubusercontent.com/molokokos89-rgb/perturabo-2.0.yaml/refs/heads/main/my_rules_proxy.json",
    "reject": "https://raw.githubusercontent.com/molokokos89-rgb/perturabo-2.0.yaml/refs/heads/main/reject_rules.json"
}

RULE_SOURCES = {
    "telegram": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/telegramcidr.txt",
    "google": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/google.txt",
    "apple": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/apple.txt",
    "youtube": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/youtube.txt",
    "tiktok": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/tiktok.txt",
    "proxy_media": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt",
    "reject": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt"
}

TIKTOK_KEYWORDS = ["tiktok", "byteoversea", "ibytedtos", "musically", "bytegecko"]
YOUTUBE_KEYWORDS = ["youtube", "ytimg", "ggpht", "googlevideo"]
TELEGRAM_KEYWORDS = ["telegram", "t.me", "tdesktop", "tx.me"]

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

PROXY_JSON = "my_rules_proxy.json"

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
    rejected_domains = set()
    
    if os.path.exists("reject_rules.json"):
        try:
            with open("reject_rules.json", "r", encoding="utf-8") as f:
                old_data = json.load(f)
                for rule in old_data.get("rules", []):
                    for d in rule.get("domain_suffix", []):
                        rejected_domains.add(d.lower().strip())
        except Exception:
            pass

    for url in AD_SOURCES:
        content = download_text(url)
        if content:
            for line in content.splitlines():
                domain = clean_domain(line)
                if domain and not is_dangerous_block(domain):
                    rejected_domains.add(domain)

    dropbox_content = download_text(DROPBOX_URL)
    if dropbox_content:
        pattern = re.compile(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})')
        for line in dropbox_content.splitlines():
            for match in pattern.finditer(line):
                item = match.group(0).lower().strip().replace("`", "").replace("*.", "")
                if len(item) > 3 and "." in item and not item.startswith("-") and not item.endswith("-"):
                    if not item.startswith(("127.", "0.", "192.168.", "10.")):
                        if not is_dangerous_block(item):
                            rejected_domains.add(item)

    existing_proxies = load_existing_proxy_domains()
    for d in existing_proxies:
        rejected_domains.discard(d)

    with open("reject_rules.json", "w", encoding="utf-8") as f:
        json.dump({"version": 1, "rules": [{"domain_suffix": sorted(list(rejected_domains))}]}, f, indent=2, ensure_ascii=False)

    collected_heavy = set()
    domain_pattern = re.compile(r'^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,6}$')

    for url in HEAVY_SOURCES:
        content = download_text(url)
        if content:
            for line in content.splitlines():
                rd = clean_domain(line)
                if rd and domain_pattern.match(rd) and len(rd) > 3:
                    if rd not in existing_proxies:
                        if not any(rd.endswith(zone) for zone in [".ru", ".su", ".by", ".xn--p1ai"]):
                            collected_heavy.add(rd)

    if collected_heavy:
        blocked_list, allowed_list = check_domains_availability(collected_heavy)
        
        with open("blocked.json", "w", encoding="utf-8") as f:
            json.dump({"version": 1, "rules": [{"domain_suffix": blocked_list}]}, f, indent=2, ensure_ascii=False)
            
        with open("allowed.json", "w", encoding="utf-8") as f:
            json.dump({"version": 1, "rules": [{"domain_suffix": allowed_list}]}, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    main()
