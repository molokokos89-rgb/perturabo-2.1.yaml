import sys
import re
import json
import base64
import socket
import urllib.request
import urllib.parse
import subprocess
import os

def safe_b64decode(data):
    data = data.strip()
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.b64decode(data).decode('utf-8', errors='ignore')

def extract_host(line):
    line = line.strip()
    if not line:
        return None
    try:
        if line.startswith("ss://"):
            part = line.split("://")[1].split("#")[0]
            host_port = part.split("@")[1] if "@" in part else safe_b64decode(part).split("@")[1]
            return host_port.split(":")[0]
        elif line.startswith(("trojan://", "hy2://", "hysteria2://", "vless://")):
            part = line.split("://")[1].split("@")[1]
            return part.split(":")[0].split("?")[0]
        elif line.startswith("vmess://"):
            b64_str = line.split("://")[1]
            data = json.loads(safe_b64decode(b64_str))
            return data.get("add")
    except Exception:
        return None
    return None

def test_domain_is_blocked_via_ru(domain):
    try:
        req = urllib.request.Request(f"https://{domain}", headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as res:
            html = res.read().decode('utf-8', errors='ignore').lower()
            if any(w in html for w in ["заблокирован", "роскомнадзор", "block", "deny"]):
                return True
            return False
    except Exception:
        return True

def load_domains_from_sources():
    if not os.path.exists("urls.txt"):
        return []
    with open("urls.txt", "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]
    
    all_extracted = []
    for index, url in enumerate(urls):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read()
                if url.endswith(".json"):
                    data = json.loads(content.decode('utf-8'))
                    if "payload" in data: all_extracted.extend(data["payload"])
                    if "rules" in data:
                        for rule in data["rules"]:
                            if "domain" in rule: all_extracted.extend(rule["domain"])
                            if "domain_suffix" in rule: all_extracted.extend(rule["domain_suffix"])
                elif url.endswith(".txt"):
                    for line in content.decode('utf-8', errors='ignore').splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            all_extracted.append(line.split(",")[-1] if "," in line else line)
                elif url.endswith(".srs"):
                    srs_file = f"temp_{index}.srs"
                    json_file = f"temp_{index}.json"
                    with open(srs_file, "wb") as out: out.write(content)
                    subprocess.run(["sing-box", "rule-set", "decompile", srs_file, "--output", json_file], check=True)
                    with open(json_file, "r", encoding="utf-8") as jf:
                        data = json.load(jf)
                    for rule in data.get("rules", []):
                        if "domain" in rule: all_extracted.extend(rule["domain"])
                        if "domain_suffix" in rule: all_extracted.extend(rule["domain_suffix"])
                    if os.path.exists(srs_file): os.remove(srs_file)
                    if os.path.exists(json_file): os.remove(json_file)
        except Exception:
            pass

    clean_domains = []
    for d in all_extracted:
        d_clean = d.strip().split(",")[-1] if "," in d else d.strip()
        if d_clean and not d_clean.startswith("+."):
            clean_domains.append(d_clean.replace("*.", ""))
    return list(set(clean_domains))

def main():
    if os.path.exists("raw_combined.txt"):
        with open("raw_combined.txt", "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
        if lines:
            raw_text = "\n".join(sorted(list(set(lines))))
            b64_output = base64.b64encode(raw_text.encode('utf-8')).decode('utf-8')
            with open("proxy.txt", "w", encoding="utf-8") as f:
                f.write(b64_output)

    if os.path.exists("ru_nodes.txt"):
        with open("ru_nodes.txt", "r", encoding="utf-8") as f:
            ru_lines = [l.strip() for l in f if l.strip()]
            if ru_lines:
                ru_raw_text = "\n".join(ru_lines)
                ru_b64 = base64.b64encode(ru_raw_text.encode('utf-8')).decode('utf-8')
                with open("ru_proxies.txt", "w", encoding="utf-8") as rf:
                    rf.write(ru_b64)

    domains_to_test = load_domains_from_sources()
    blocked_list = []
    allowed_list = []

    for domain in domains_to_test:
        if test_domain_is_blocked_via_ru(domain):
            blocked_list.append(domain)
        else:
            allowed_list.append(domain)

    with open("blocked.json", "w", encoding="utf-8") as f:
        json.dump({"version": 1, "rules": [{"domain_suffix": blocked_list}]}, f, indent=2)
    with open("allowed.json", "w", encoding="utf-8") as f:
        json.dump({"version": 1, "rules": [{"domain_suffix": allowed_list}]}, f, indent=2)

if __name__ == "__main__":
    main()
