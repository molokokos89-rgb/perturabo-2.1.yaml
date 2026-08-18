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

def load_json(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return {"version": 1, "rules": []}

def load_json(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return {"version": 1, "rules": []}

def fetch_external_domains(url):
    domains = set()
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            if url.endswith(".json"):
                data = json.loads(response.read().decode('utf-8'))
                for rule in data.get("rules", []):
                    if "domain" in rule: domains.update(rule["domain"])
                    if "domain_suffix" in rule: domains.update(rule["domain_suffix"])
            else:
                content = response.read().decode('utf-8', errors='ignore')
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith('!'):
                        continue
                    cleaned = re.sub(r'^[|]*', '', line)
                    cleaned = cleaned.split('$')[0].split('^')[0].split('/')[0].strip()
                    if cleaned and '.' in cleaned and not cleaned.startswith('127.') and not cleaned.startswith('0.'):
                        domains.add(cleaned)
    except Exception as e:
        print(f"Error loading {url}: {e}")
    return domains

data = load_json('reject_rules.json')

external_items = set()
for url in EXTERNAL_REJECT_URLS:
    external_items.update(fetch_external_domains(url))

final_domains = set()
final_ips = set()

ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

for item in external_items:
    item_clean = item.strip().replace("`", "").replace("*.", "")
    if ip_pattern.match(item_clean):
        final_ips.add(f"{item_clean}/32")
    else:
        final_domains.add(item_clean)

if 'rules' in data and data['rules']:
    for rule in data['rules']:
        if 'domain_suffix' in rule:
            for item in rule['domain_suffix']:
                item_clean = item.strip().replace("`", "").replace("*.", "")
                if item not in external_items:
                    if ip_pattern.match(item_clean):
                        final_ips.add(f"{item_clean}/32")
                    else:
                        final_domains.add(item_clean)
        if 'ip_cidr' in rule:
            for item in rule['ip_cidr']:
                item_clean = item.strip().replace("`", "")
                if '/' in item_clean:
                    final_ips.add(item_clean)
                elif ip_pattern.match(item_clean):
                    final_ips.add(f"{item_clean}/32")

vetted_domains = set()
for d in final_domains:
    if not isinstance(d, str): continue
    d_clean = d.strip().replace("`", "").replace("*.", "")
    if len(d_clean) > 3 and "." in d_clean and not d_clean.startswith("-") and not d_clean.endswith("-"):
        vetted_domains.add(d_clean.lower())

rule_list = []
if vetted_domains:
    rule_list.append({"domain_suffix": sorted(list(vetted_domains))})
if final_ips:
    rule_list.append({"ip_cidr": sorted(list(final_ips))})

data['version'] = 1
data['rules'] = rule_list

with open('reject_rules.json', 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

print(f"reject_rules.json updated successfully in version 1!")
