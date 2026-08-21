import json
import re
import urllib.request
import os

RUS_JSON = "My_rules_RUS.json"
REJECT_JSON = "reject_rules.json"
PROXY_JSON = "my_rules_proxy.json"

DROPBOX_URL = "https://dropbox.com"

TIKTOK_KEYWORDS = ["tiktok", "byteoversea", "ibytedtos", "musically", "bytegecko"]
YOUTUBE_KEYWORDS = ["youtube", "ytimg", "ggpht", "googlevideo"]
TELEGRAM_KEYWORDS = ["telegram", "t.me", "tdesktop", "tx.me"]

def load_or_create_json(file_path):
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
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
            pattern = re.compile(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})')
            for line in content.splitlines():
                for match in pattern.finditer(line):
                    item = match.group(0).lower().strip().replace("`", "").replace("*.", "")
                    if len(item) > 3 and "." in item and not item.startswith("-") and not item.endswith("-"):
                        if not item.startswith(("127.", "0.", "192.168.", "10.")):
                            extracted.add(item)
    except Exception:
        pass
    return extracted

def update_rule_set(file_name, new_domains):
    data = load_or_create_json(file_name)
    existing_domains = set()
    
    if 'rules' in data and data['rules']:
        for rule in data['rules']:
            if 'domain_suffix' in rule: 
                existing_domains.update(rule['domain_suffix'])
                
    existing_domains.update(new_domains)
    data['version'] = 1
    data['rules'] = [{"domain_suffix": sorted(list(existing_domains))}]
    
    with open(file_name, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def main():
    raw_items = extract_items_from_dropbox()
    if not raw_items:
        return

    rus_domains = set()
    proxy_domains = set()

    for item in raw_items:
        is_tg = any(kw in item for kw in TELEGRAM_KEYWORDS)
        is_tiktok = any(kw in item for kw in TIKTOK_KEYWORDS)
        is_youtube = any(kw in item for kw in YOUTUBE_KEYWORDS)
        
        if is_tg or is_tiktok or is_youtube:
            proxy_domains.add(item)
            continue
            
        if any(item.endswith(zone) for zone in [".ru", ".su", ".by", ".xn--p1ai"]):
            rus_domains.add(item)
            continue
            
        proxy_domains.add(item)

    if rus_domains:
        update_rule_set(RUS_JSON, rus_domains)
    if proxy_domains:
        update_rule_set(PROXY_JSON, proxy_domains)

if __name__ == "__main__":
    main()
