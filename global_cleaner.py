import json
import os
import re

FILES_TO_CLEAN = ["my_rules_proxy.json", "My_rules_RUS.json", "reject_rules.json"]

def is_valid_domain(domain):
    pattern = re.compile(r'^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,6}$')
    return bool(pattern.match(domain))

def load_and_clean_file(file_path):
    if not os.path.exists(file_path):
        return set()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return set()
    
    cleaned = set()
    for rule in data.get("rules", []):
        for key in ["domain_suffix", "domain"]:
            if key in rule:
                for d in rule[key]:
                    d = d.strip().lower().replace("`", "").replace("*.", "")
                    if d.startswith("."):
                        d = d[1:]
                    if is_valid_domain(d) and len(d) > 3:
                        if not any(d.startswith(ip) for ip in ["127.", "0.", "192.168.", "10."]):
                            cleaned.add(d)
    return cleaned

def save_json_file(file_path, domains):
    output = {
        "version": 1,
        "rules": [{"domain_suffix": sorted(list(domains))}]
    }
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

def main():
    proxy_set = load_and_clean_file("my_rules_proxy.json")
    rus_set = load_and_clean_file("My_rules_RUS.json")
    reject_set = load_and_clean_file("reject_rules.json")

    for d in proxy_set:
        reject_set.discard(d)
        rus_set.discard(d)
    for d in rus_set:
        reject_set.discard(d)

    save_json_file("my_rules_proxy.json", proxy_set)
    save_json_file("My_rules_RUS.json", rus_set)
    save_json_file("reject_rules.json", reject_set)

if __name__ == "__main__":
    main()
