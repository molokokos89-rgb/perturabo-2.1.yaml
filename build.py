import json
import re
import urllib.request
import os
import ipaddress

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

def download_text(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.read().decode('utf-8', errors='ignore')
    except Exception:
        return ""

def load_remote_json(url):
    try:
        content = download_text(url)
        if content:
            return json.loads(content)
    except Exception:
        pass
    return {"version": 1, "rules": []}

def extract_domains_from_json(data):
    domains = set()
    for rule in data.get("rules", []):
        if "domain_suffix" in rule:
            for d in rule["domain_suffix"]:
                domains.add(d.lower().strip())
    return domains

def is_ip(item):
    try:
        ipaddress.ip_address(item)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(item, strict=False)
        return True
    except ValueError:
        pass
    return False

def clean_item(item):
    item = item.lower().strip().replace("`", "").replace("*.", "")
    if item.startswith("."):
        item = item[1:]
    return item

def check_against_sources(item, cache):
    for key, url in RULE_SOURCES.items():
        if key not in cache:
            cache[key] = download_text(url).lower()
        if item in cache[key]:
            return key
    return None

def save_json_file(file_path, domains):
    output = {
        "version": 1,
        "rules": [{"domain_suffix": sorted(list(domains))}]
    }
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

def main():
    sources_cache = {}
    
    rus_domains = extract_domains_from_json(load_remote_json(MAIN_REPO_RULES["rus"]))
    proxy_domains = extract_domains_from_json(load_remote_json(MAIN_REPO_RULES["proxy"]))
    reject_domains = extract_domains_from_json(load_remote_json(MAIN_REPO_RULES["reject"]))
    
    dropbox_content = download_text(DROPBOX_URL)
    if not dropbox_content:
        return

    pattern = re.compile(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})')
    
    for line in dropbox_content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!", ";")):
            continue
        
        matches = pattern.finditer(line)
        for match in matches:
            item = clean_item(match.group(0))
            if len(item) <= 3 or not "." in item or item.startswith("-") or item.endswith("-"):
                continue
            if item.startswith(("127.", "0.", "192.168.", "10.")):
                continue
            if is_ip(item):
                continue

            if any(kw in item for kw in TELEGRAM_KEYWORDS) or any(kw in item for kw in YOUTUBE_KEYWORDS) or any(kw in item for kw in TIKTOK_KEYWORDS):
                proxy_domains.add(item)
                continue

            matched_source = check_against_sources(item, sources_cache)
            
            if matched_source == "reject":
                reject_domains.add(item)
            elif matched_source in ["telegram", "google", "apple", "youtube", "tiktok", "proxy_media"]:
                proxy_domains.add(item)
            else:
                if any(item.endswith(zone) for zone in [".ru", ".su", ".by", ".xn--p1ai"]):
                    rus_domains.add(item)
                else:
                    proxy_domains.add(item)

    for d in proxy_domains:
        reject_domains.discard(d)
    for d in rus_domains:
        reject_domains.discard(d)

    save_json_file(RUS_JSON, rus_domains)
    save_json_file(PROXY_JSON, proxy_domains)
    save_json_file(REJECT_JSON, reject_domains)

if __name__ == "__main__":
    main()
