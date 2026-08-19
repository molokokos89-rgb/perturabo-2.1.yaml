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
BAD_KEYWORDS = ["anycast", "fixnet", "fixcord", "cloudflare", "warp", "cf-"]

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

def is_russian_proxy(line_str):
    line_lower = line_str.lower()
    return any(ru_kw in line_lower for ru_kw in RU_KEYWORDS)

def get_rkn_banned_list():
    rkn_url = "https://raw.githubusercontent.com/roskomkod/ru-blocked-domains/main/domains.txt"
    try:
        req = urllib.request.Request(rkn_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode('utf-8', errors='ignore')
            return set(line.strip().lower() for line in content.splitlines() if line.strip() and not line.startswith("#"))
    except Exception:
        return set()

def test_domain_via_ru_proxy(domain, ru_nodes):
    if not ru_nodes:
        return True

    ru_node = ru_nodes[0]
    host = extract_host(ru_node)
    if not host:
        return True

    try:
        port = 443
        if "@" in ru_node and ":" in ru_node.split("@")[-1]:
            port_part = ru_node.split("@")[-1].split(":")[1]
            port = int(re.split(r'[/?#]', port_part)[0])

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((host, port))
        sock.close()

        if result != 0:
            return True

        proxy_url = f"http://{host}:{port}"
        proxy_support = urllib.request.ProxyHandler({'http': proxy_url, 'https': proxy_url})
        opener = urllib.request.build_opener(proxy_support)
        
        req = urllib.request.Request(
            f"https://{domain}", 
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        
        with opener.open(req, timeout=4) as res:
            html = res.read().decode('utf-8', errors='ignore').lower()
            if any(w in html for w in ["заблокирован", "роскомнадзор", "eais", "block", "deny"]):
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
                        line = line.strip()
                        if line and not line.startswith("#"):
                            domain = line.split(",")[-1] if "," in line else line
                            all_extracted.append(domain)
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
        d_clean = d.strip().split(",")[-1] if "," in d else d.strip()
        if d_clean and not d_clean.startswith("+."): 
            clean_domains.append(d_clean)
            
    return list(set(clean_domains))

def main():
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
        if not line_str or line_str.startswith("vless://"):
            continue
            
        if is_russian_proxy(line_str):
            host = extract_host(line_str)
            if host:
                ru_lines.append(line_str)
            continue

        if any(bad in line_str.lower() for bad in BAD_KEYWORDS):
            continue

        host = extract_host(line_str)
        if host:
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

    ru_nodes = unique_ru_lines

    rkn_domains = get_rkn_banned_list()
    domains_to_test = load_domains_from_sources()
    
    proxy_rules = list(rkn_domains)
    rus_rules = []
    
    for domain in domains_to_test:
        d_clean = domain.lower()
        if d_clean not in rkn_domains and not any(d_clean.endswith("." + rkn_d) for rkn_d in rkn_domains):
            if test_domain_via_ru_proxy(domain, ru_nodes):
                proxy_rules.append(domain)
            else:
                rus_rules.append(domain)

    with open("my_rules_proxy.json", "w", encoding="utf-8") as f:
        json.dump({"version": 1, "rules": [{"domain": sorted(list(set(proxy_rules)))}]}, f, separators=(',', ':'))

    with open("My_rules_RUS.json", "w", encoding="utf-8") as f:
        json.dump({"version": 1, "rules": [{"domain": sorted(list(set(rus_rules)))}]}, f, separators=(',', ':'))

if __name__ == "__main__":
    main()