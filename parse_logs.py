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

def fetch_json_rules(url):
    domains = set()
    ips = set()
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode('utf-8', errors='ignore'))
            if 'rules' in data:
                for rule in data['rules']:
                    if 'domain_suffix' in rule: domains.update(rule['domain_suffix'])
                    if 'ip_cidr' in rule: ips.update(rule['ip_cidr'])
    except Exception:
        pass
    return domains, ips

def load_global_rules(url):
    rules = set()
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split(',')
                    val = parts[1].strip() if len(parts) > 1 else parts[0].strip()
                    val = val.replace("`", "").replace("*.", "").lower()
                    rules.add(val)
    except Exception:
        pass
    return rules

def load_or_create_json(file_path):
    for root, dirs, files in os.walk("."):
        if os.path.basename(file_path) in files:
            try:
                with open(os.path.join(root, file_path), 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
    return {"version": 1, "rules": []}

def extract_items_from_dropbox():
    extracted = set()
    try:
        req = urllib.request.Request(DROPBOX_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode('utf-8', errors='ignore')
            pattern = re.compile(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}(:\d+)?)|((\d{1,3}\.){3}\d{1,3})')
            for line in content.splitlines():
                for match in pattern.finditer(line):
                    item = match.group(0).split(':')[0].lower().strip()
                    item = item.replace("`", "").replace("*.", "")
                    if len(item) > 3 and "." in item and not item.startswith("-") and not item.endswith("-"):
                        if not item.startswith("127.") and not item.startswith("0."):
                            extracted.add(item)
    except Exception:
        pass
    return extracted

def update_rule_set(file_name, new_domains, new_ips):
    data = load_or_create_json(file_name)
    existing_domains = set()
    existing_ips = set()
    
    if 'rules' in data and data['rules']:
        for rule in data['rules']:
            if 'domain_suffix' in rule: existing_domains.update(rule['domain_suffix'])
            if 'ip_cidr' in rule: existing_ips.update(rule['ip_cidr'])
            
    existing_domains.update(new_domains)
    existing_ips.update(new_ips)
    
    rule_list = []
    if existing_domains:
        rule_list.append({"domain_suffix": sorted(list(existing_domains))})
    if existing_ips:
        rule_list.append({"ip_cidr": sorted(list(existing_ips))})
        
    data['version'] = 1
    data['rules'] = rule_list
    
    target_path = file_name
    for root, dirs, files in os.walk("."):
        if file_name in files:
            target_path = os.path.join(root, file_name)
            break
            
    with open(target_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def main():
    main_rus_doms, main_rus_ips = fetch_json_rules(MAIN_REPO_RULES["rus"])
    main_proxy_doms, main_proxy_ips = fetch_json_rules(MAIN_REPO_RULES["proxy"])
    main_reject_doms, main_reject_ips = fetch_json_rules(MAIN_REPO_RULES["reject"])

    tg_rules = load_global_rules(RULE_SOURCES["telegram"])
    google_rules = load_global_rules(RULE_SOURCES["google"])
    apple_rules = load_global_rules(RULE_SOURCES["apple"])
    yt_rules = load_global_rules(RULE_SOURCES["youtube"])
    tiktok_rules = load_global_rules(RULE_SOURCES["tiktok"])
    media_rules = load_global_rules(RULE_SOURCES["proxy_media"])
    global_reject_rules = load_global_rules(RULE_SOURCES["reject"])
    
    proxy_global_set = tg_rules | google_rules | apple_rules | yt_rules | tiktok_rules | media_rules

    raw_items = extract_items_from_dropbox()
    if not raw_items:
        return

    rus_domains, rus_ips = set(), set()
    reject_domains, reject_ips = set(), set()
    proxy_domains, proxy_ips = set(), set()
    
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

    for item in raw_items:
        is_ip = bool(ip_pattern.match(item))
        item_ip_cidr = f"{item}/32" if is_ip else ""

        if (item in main_reject_doms or item_ip_cidr in main_reject_ips or
            item in main_proxy_doms or item_ip_cidr in main_proxy_ips or
            item in main_rus_doms or item_ip_cidr in main_rus_ips):
            continue

        if any(reject_item in item for reject_item in global_reject_rules):
            if is_ip: reject_ips.add(item_ip_cidr)
            else: reject_domains.add(item)
            continue

        is_tiktok = any(kw in item for kw in TIKTOK_KEYWORDS)
        is_youtube = any(kw in item for kw in YOUTUBE_KEYWORDS)
        is_in_proxy_rules = any(proxy_item in item for proxy_item in proxy_global_set)

        if is_tiktok or is_youtube or is_in_proxy_rules:
            if is_ip: proxy_ips.add(item_ip_cidr)
            else: proxy_domains.add(item)
            continue

        if any(item.endswith(zone) for zone in [".ru", ".su", ".by", ".xn--p1ai"]):
            if is_ip: rus_ips.add(item_ip_cidr)
            else: rus_domains.add(item)
            continue

        if is_ip: proxy_ips.add(item_ip_cidr)
        else: proxy_domains.add(item)

    if rus_domains or rus_ips:
        update_rule_set(RUS_JSON, rus_domains, rus_ips)
    if reject_domains or reject_ips:
        update_rule_set(REJECT_JSON, reject_domains, reject_ips)
    if proxy_domains or proxy_ips:
        update_rule_set(PROXY_JSON, proxy_domains, proxy_ips)

if __name__ == "__main__":
    main()