import json
import re
import urllib.request
import os

LOG_FILE = "karing_logs.txt"
RUS_JSON = "My_rules_RUS.json"
REJECT_JSON = "reject_rules.json"
PROXY_JSON = "my_rules_proxy.json"

AD_KEYWORDS = ["ad", "telemetry", "analytics", "tracker", "metrics", "stats", "pixel", "banner", "popunder"]

def load_or_create_json(file_path):
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            pass
    return {"version": 1, "rules": []}

def check_is_russian(target):
    if any(target.endswith(zone) for zone in [".ru", ".su", ".by", ".xn--p1ai"]):
        return True
    
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    ip_clean = target.split('/')[0]
    
    if ip_pattern.match(ip_clean):
        try:
            req = urllib.request.Request(f"https://ipapi.co{ip_clean}/country/", headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                country = response.read().decode('utf-8').strip()
                return country == "RU"
        except:
            return True
    return False

def extract_items_from_logs():
    if not os.path.exists(LOG_FILE):
        return set()
    
    extracted = set()
    pattern = re.compile(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}(:\d+)?)|((\d{1,3}\.){3}\d{1,3})')
    
    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            for match in pattern.finditer(line):
                item = match.group(0).split(':')[0].lower().strip()
                item = item.replace("`", "").replace("*.", "")
                if len(item) > 3 and "." in item and not item.startswith("-") and not item.endswith("-"):
                    if not item.startswith("127.") and not item.startswith("0."):
                        extracted.add(item)
    return extracted

def update_rule_set(file_path, new_domains, new_ips):
    data = load_or_create_json(file_path)
    
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
    
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def main():
    raw_items = extract_items_from_logs()
    if not raw_items:
        print("No items found in logs.")
        return
        
    rus_domains, rus_ips = set(), set()
    reject_domains, reject_ips = set(), set()
    proxy_domains, proxy_ips = set(), set()
    
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    
    for item in raw_items:
        is_ru = check_is_russian(item)
        if ip_pattern.match(item):
            if is_ru: rus_ips.add(f"{item}/32")
            else:
                if any(kw in item for kw in AD_KEYWORDS): reject_ips.add(f"{item}/32")
                else: proxy_ips.add(f"{item}/32")
        else:
            if is_ru: rus_domains.add(item)
            else:
                if any(kw in item for kw in AD_KEYWORDS): reject_domains.add(item)
                else: proxy_domains.add(item)
            
    if rus_domains or rus_ips:
        update_rule_set(RUS_JSON, rus_domains, rus_ips)
    if reject_domains or reject_ips:
        update_rule_set(REJECT_JSON, reject_domains, reject_ips)
    if proxy_domains or proxy_ips:
        update_rule_set(PROXY_JSON, proxy_domains, proxy_ips)
        
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write("")
        
    print("Logs successfully parsed and distributed across 3 files!")

if __name__ == "__main__":
    main()
