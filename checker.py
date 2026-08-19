import sys
import re
import json
import base64
import socket
import urllib.request
import urllib.parse
import subprocess
import os

RU_KEYWORDS = ["russia", "moscow", "spb", "россия", "sankt-peterburg", "🇷🇺"]

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
            if "@" in part:
                host_port = part.split("@")[1]
            else:
                decoded = safe_b64decode(part)
                host_port = decoded.split("@")[1]
            return host_port.split(":")[0]
        elif line.startswith(("trojan://", "hy2://", "hysteria2://", "vless://")):
            part = line.split("://")[1].split("@")[1]
            return part.split(":")[0].split("?")[0]
        elif line.startswith("vmess://"):
            b64_str = line.split("://")[1]
            decoded = safe_b64decode(b64_str)
            data = json.loads(decoded)
            return data.get("add")
    except Exception:
        return None
    return None

def is_russian_ip(host):
    try:
        ip = socket.gethostbyname(host)
        url = f"http://ip-api.com/json/{ip}?fields=countryCode"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode('utf-8'))
            return data.get("countryCode") == "RU"
    except Exception:
        return False

def is_russian_proxy(line_str):
    line_lower = line_str.lower()
    if any(ru_kw in line_lower for ru_kw in RU_KEYWORDS):
        return True
    host = extract_host(line_str)
    if host:
        return is_russian_ip(host)
    return False

def clean_domain(domain):
    domain = domain.strip().lower()
    if "," in domain:
        domain = domain.split(",")[-1]
    domain = re.sub(r'^[.+]+', '', domain)
    domain = re.sub(r'^[a-zA-Z0-9]+://', '', domain)
    domain = domain.split('/')[0].split(':')[0]
    if domain and not domain.startswith("-") and "." in domain:
        return domain
    return None

def get_rkn_banned_list():
    rkn_url = "https://raw.githubusercontent.com/roskomkod/ru-blocked-domains/main/domains.txt"
    domains = set()
    try:
        req = urllib.request.Request(rkn_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode('utf-8', errors='ignore')
            for line in content.splitlines():
                if line.strip() and not line.startswith("#"):
                    cleaned = clean_domain(line)
                    if cleaned:
                        domains.add(cleaned)
    except Exception:
        pass
    return domains

def load_domains_from_sources():
    if not os.path.exists("urls.txt"):
        return []
    
    with open("urls.txt", "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]
        
    all_extracted = []
    for index, url in enumerate(urls):
        if url.endswith(".json"):
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=10) as response:
                    data = json.loads(response.read().decode('utf-8'))
                    if "payload" in data:
                        all_extracted.extend(data["payload"])
                    if "rules" in data:
                        for rule in data["rules"]:
                            if "domain" in rule: all_extracted.extend(rule["domain"])
                            if "domain_suffix" in rule: all_extracted.extend(rule["domain_suffix"])
            except Exception:
                pass
        elif url.endswith(".txt"):
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=10) as response:
                    for line in response.read().decode('utf-8', errors='ignore').splitlines():
                        if line.strip() and not line.startswith("#"):
                            all_extracted.append(line)
            except Exception:
                pass
        elif url.endswith(".srs"):
            srs_file = f"temp_{index}.srs"
            json_file = f"temp_{index}.json"
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=10) as response:
                    with open(srs_file, "wb") as out:
                        out.write(response.read())
                subprocess.run(["sing-box", "rule-set", "decompile", srs_file, "--output", json_file], check=True)
                with open(json_file, "r", encoding="utf-8") as jf:
                    data = json.load(jf)
                    for rule in data.get("rules", []):
                        if "domain" in rule: all_extracted.extend(rule["domain"])
                        if "domain_suffix" in rule: all_extracted.extend(rule["domain_suffix"])
            except Exception:
                pass
            finally:
                if os.path.exists(srs_file): os.remove(srs_file)
                if os.path.exists(json_file): os.remove(json_file)
            
    clean_domains = []
    for d in all_extracted:
        cd = clean_domain(d)
        if cd:
            clean_domains.append(cd)
            
    return list(set(clean_domains))

def main():
    os.makedirs("rules", exist_ok=True)
    
    target_files = ["proxy.txt", "ru_nodes.txt", "ru_proxies.txt", "My_rules_RUS.json", "my_rules_proxy.json", "reject_rules.json"]
    for name in target_files:
        if not os.path.exists(name):
            open(name, "a", encoding="utf-8").close()

    lines = []
    if os.path.exists("raw_combined.txt"):
        with open("raw_combined.txt", "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

    clean_lines = []
    ru_lines = []

    for line in lines:
        line_str = line.strip()
        if not line_str:
            continue
            
        host = extract_host(line_str)
        if not host:
            continue

        if is_russian_proxy(line_str):
            ru_lines.append(line_str)
        else:
            clean_lines.append(line_str)

    unique_ru_lines = sorted(list(set(ru_lines)))
    ru_raw_text = "\n".join(unique_ru_lines)
    ru_b64_output = base64.b64encode(ru_raw_text.encode('utf-8')).decode('utf-8') if ru_raw_text else ""

    with open("ru_proxies.txt", "w", encoding="utf-8") as f:
        f.write(ru_b64_output)

    with open("ru_nodes.txt", "w", encoding="utf-8") as f:
        f.write(ru_raw_text)

    unique_lines = sorted(list(set(clean_lines)))
    raw_text = "\n".join(unique_lines)
    b64_output = base64.b64encode(raw_text.encode('utf-8')).decode('utf-8') if raw_text else ""

    with open("proxy.txt", "w", encoding="utf-8") as f:
        f.write(b64_output)

    rkn_domains = get_rkn_banned_list()
    user_domains = load_domains_from_sources()

    proxy_domains = set(rkn_domains)
    rus_domains = set()

    for d in user_domains:
        if d in rkn_domains or any(d.endswith("." + rkn) for rkn in rkn_domains):
            proxy_domains.add(d)
        else:
            rus_domains.add(d)

    sorted_proxy_domains = sorted(list(proxy_domains))
    chunk_size = 2000
    chunks = [sorted_proxy_domains[i:i + chunk_size] for i in range(0, len(sorted_proxy_domains), chunk_size)]

    for idx, chunk in enumerate(chunks, 1):
        filename = f"rules/block{idx}.json"
        payload = {
            "version": 1,
            "rules": [
                {
                    "domain_suffix": chunk
                }
            ]
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, separators=(',', ':'))

    main_proxy_payload = {
        "version": 1,
        "rules": [
            {
                "domain_suffix": sorted_proxy_domains
            }
        ]
    }
    with open("my_rules_proxy.json", "w", encoding="utf-8") as f:
        json.dump(main_proxy_payload, f, ensure_ascii=False, separators=(',', ':'))

    rus_payload = {
        "version": 1,
        "rules": [
            {
                "domain_suffix": sorted(list(rus_domains))
            }
        ]
    }
    with open("My_rules_RUS.json", "w", encoding="utf-8") as f:
        json.dump(rus_payload, f, ensure_ascii=False, separators=(',', ':'))

if __name__ == "__main__":
    main()