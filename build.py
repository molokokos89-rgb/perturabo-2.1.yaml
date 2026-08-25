import os
import sys
import re
import json
import socket
import base64
import urllib.request
import urllib.parse
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

RUS_JSON = "My_rules_RUS.json"
REJECT_JSON = "reject_rules.json"
PROXY_JSON = "my_rules_proxy.json"

PROXY_MANUAL_TXT = "proxy_manual.txt"
DIRECT_MANUAL_TXT = "direct_manual.txt"
REJECT_MANUAL_TXT = "reject_manual.txt"

DROPBOX_URL = "https://www.dropbox.com/scl/fi/759t1a2us3y0kblgat0xr/log-for-reject.txt?rlkey=zr2uqv81lx89rdl6q55geyucy&st=8lc13ygu&dl=1"

SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS%2BAll_RUS.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/hy2.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    "https://raw.githubusercontent.com/freefq/free/master/v2ray",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt"
]

RULE_SOURCES = {
    "telegram": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/telegramcidr.txt",
    "google": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/google.txt",
    "apple": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/apple.txt",
    "youtube": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/youtube.txt",
    "tiktok": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/tiktok.txt",
    "proxy_media": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt",
    "reject": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt",
    "adguard_dns": "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/DNSFilter/sections/adservers.txt",
    "adguard_trackers": "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/DNSFilter/sections/spyware.txt",
    "oisd_small": "https://small.oisd.nl/domainswild",
    "stevenblack": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
}

HEAVY_SOURCES = [
    "https://raw.githubusercontent.com/roskomkod/ru-blocked-domains/main/domains.txt"
]

PROTOCOLS = ["ss://", "vmess://", "trojan://", "hy2://", "hysteria2://", "vless://"]
BAD_KEYWORDS = ["russia", "anycast", "fixnet", "fixcord", "cloudflare", "warp", "cf-"]

TELEGRAM_DOMAINS = [
    "t.me", "telegram.org", "telegram.me", "tdesktop.com", "telegra.ph", 
    "telegram.dog", "tx.me", "usercontent.dev"
]

TELEGRAM_CIDRS = [
    "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22",
    "91.108.20.0/22", "91.108.24.0/22", "91.108.56.0/22", "149.154.160.0/20",
    "149.154.164.0/22", "149.154.168.0/22", "149.154.172.0/22", "185.76.151.0/24",
    "200.1.1.0/24"
]

WILDBERRIES_CIDRS = [
    "31.13.24.0/21", "87.240.129.0/24", "87.240.131.0/24", "87.240.132.0/24",
    "87.240.137.0/24", "87.240.139.0/24", "95.142.204.0/22", "95.142.208.0/22",
    "178.248.232.0/21", "178.248.240.0/21"
]

AD_TRACKER_KEYWORDS = [
    "analytics", "ads", "pixel", "metrics", "telemetry", "tracker",
    "tracking", "adservice", "adsystem", "banner", "counter", "pangle",
    "bdtone", "doubleclick", "app-measurement", "adjust", "appsflyer"
]

DOMESTIC_EXCLUSIONS = [
    "yandex", "ya.ru", "yastatic", "kinopoisk", "dzen", "vk.com", 
    "vk.ru", "mail.ru", "ok.ru", "rutube", "gosuslugi", "sberbank", "tbank", "tinkoff",
    "ident.me"
]

def fetch_url(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8', errors='ignore')
        if not any(proto in content for proto in PROTOCOLS):
            try:
                clean_content = content.strip().replace("\n", "").replace("\r", "")
                missing_padding = len(clean_content) % 4
                if missing_padding:
                    clean_content += '=' * (4 - missing_padding)
                clean_content = clean_content.replace('-', '+').replace('_', '/')
                content = base64.b64decode(clean_content).decode('utf-8', errors='ignore')
            except Exception:
                pass
        return content
    except Exception:
        return ""

def safe_b64decode(data):
    data = data.strip()
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    data = data.replace('-', '+').replace('_', '/')
    return base64.b64decode(data).decode('utf-8', errors='ignore')

def extract_ip_or_domain(proxy_link):
    try:
        clean_link = re.sub(r'^[a-zA-Z0-9\-\.]+://', '', proxy_link)
        server_part = clean_link.split('@')[-1] if '@' in clean_link else clean_link
        return re.split(r'[:/?#]', server_part)[0].strip()
    except Exception:
        return None

def extract_host(line):
    line = line.strip()
    if not line:
        return None
    try:
        if line.startswith("ss://"):
            part = line.split("://")[1].split("#")[0]
            host_port = part.split("@")[1] if "@" in part else safe_b64decode(part).split("@")[1]
            return host_port.split(":")[0].strip("[]")
        elif line.startswith(("trojan://", "hy2://", "hysteria2://", "vless://", "tuic://")):
            part = line.split("://")[1].split("@")[1] if "@" in line else line.split("://")[1]
            return part.split(":")[0].split("?")[0].strip("[]")
        elif line.startswith("vmess://"):
            decoded = safe_b64decode(line.split("://")[1].split("?")[0])
            data = json.loads(decoded)
            return str(data.get("add")).strip("[]") if data.get("add") else None
    except Exception:
        return None
    return None

def is_valid_reality(proxy_link):
    if not proxy_link.startswith("vless://"):
        return True
    if "security=reality" not in proxy_link.lower() or "pbk=" not in proxy_link.lower():
        return False
    sni_match = re.search(r'[?&]sni=([^&]+)', proxy_link, re.IGNORECASE)
    if sni_match:
        sni = sni_match.group(1).split('#')[0].lower()
        if any(kw in sni for kw in ["google", "netflix", "facebook", "instagram", "twitter", "youtube"]):
            return False
    return True

def check_is_russia(host):
    if not host:
        return False
    if host.lower().endswith(('.ru', '.su', '.by')):
        return True
    try:
        ip = host if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host) else socket.gethostbyname(host)
        req = urllib.request.Request(f"http://ip-api.com/json/{ip}", headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode('utf-8'))
            if data.get("status") == "success" and data.get("countryCode") == "RU":
                return True
    except Exception:
        pass
    return False

def clean_domain(line):
    if not line:
        return None
    line = line.strip().lower()
    if not line or line.startswith(("#", "!", ";", "//", "@")):
        return None
    line = re.sub(r'^(127\.0\.0\.1|0\.0\.0\.0|::1)\s+', '', line)
    if "#" in line:
        line = line.split("#")[0]
    line = line.strip().replace("||", "").replace("^", "").strip(".-")
    line = re.sub(r'^[a-z0-9]+://', '', line).split('/')[0].split('?')[0].split(':')[0]
    if not line or len(line) < 4 or len(line) > 60:
        return None
    if re.search(r'\.(js|css|png|jpg|jpeg|svg|gif|woff|woff2|json|ico|xml)$', line):
        return None
    domain_regex = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
    if re.match(domain_regex, line):
        if any(line.startswith(pfx) for pfx in ["127.", "0.", "192.168.", "10.", "172."]):
            return None
        return line
    return None

def is_telegram_domain(domain):
    return any(tg in domain.lower() for tg in TELEGRAM_DOMAINS) or "telegram" in domain.lower()

def is_domestic_service(domain):
    if is_telegram_domain(domain):
        return False
    domain_lower = domain.lower()
    if any(dom in domain_lower for dom in DOMESTIC_EXCLUSIONS):
        return True
    if any(domain_lower.endswith(zone) for zone in [".ru", ".su", ".by", ".xn--p1ai"]):
        return True
    return False

def is_ad_or_tracker(domain):
    if is_telegram_domain(domain):
        return False
    return any(keyword in domain.lower() for keyword in AD_TRACKER_KEYWORDS)

def load_links_from_txt(filename):
    urls = []
    if os.path.exists(filename):
        with open(filename, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith(("#", "//")):
                    urls.append(line)
    return urls

def process_url_content(url, domains_set, cidrs_set=None):
    content = fetch_url(url)
    if not content:
        return
    if content.strip().startswith(("{", "[")):
        try:
            data = json.loads(content)
            items = []
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                if "payload" in data:
                    items = data["payload"]
                elif "rules" in data:
                    for rule in data["rules"]:
                        items.extend(rule.get("domain_suffix", []))
                        items.extend(rule.get("domain", []))
                        items.extend(rule.get("ip_cidr", []))
            for item in items:
                if isinstance(item, str):
                    if "/" in item and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+$', item):
                        if cidrs_set is not None:
                            cidrs_set.add(item)
                    else:
                        d = clean_domain(item)
                        if d:
                            domains_set.add(d)
        except Exception:
            pass
        return
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!", ";", "//")):
            continue
        if cidrs_set is not None and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d+)?$', line.split(',')[0].strip()):
            cidr = line.split(",")[-1].strip()
            cidrs_set.add(cidr)
            continue
        d = clean_domain(line)
        if d:
            domains_set.add(d)

def load_json_domains(filename):
    domains = set()
    if os.path.exists(filename):
        try:
            with open(filename, "r", encoding="utf-8") as f:
                data = json.load(f)
                items = data.get("payload", [])
                if not items and "rules" in data:
                    for rule in data.get("rules", []):
                        items.extend(rule.get("domain_suffix", []))
                        items.extend(rule.get("domain", []))
                for d in items:
                    cd = clean_domain(d)
                    if cd:
                        domains.add(cd)
        except Exception:
            pass
    return domains

def save_mixed_rules_file(filename, domains, cidrs):
    existing_domains = set()
    existing_cidrs = set()
    if os.path.exists(filename):
        try:
            with open(filename, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "rules" in data and data["rules"]:
                    for rule in data["rules"]:
                        existing_domains.update(rule.get("domain_suffix", []))
                        existing_cidrs.update(rule.get("ip_cidr", []))
        except Exception:
            pass

    combined_domains = existing_domains | set(domains)
    combined_cidrs = existing_cidrs | set(cidrs)

    sorted_domains = sorted(list(combined_domains))
    sorted_cidrs = sorted(list(combined_cidrs))

    rule_item = {}
    if sorted_domains:
        rule_item["domain_suffix"] = sorted_domains
    if sorted_cidrs:
        rule_item["ip_cidr"] = sorted_cidrs

    data = {
        "version": 1,
        "rules": [rule_item] if rule_item else []
    }

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def parse_proxy_to_singbox(link):
    try:
        if link.startswith("ss://"):
            if "@" in link:
                part = link.split("://")[1]
                b64_userinfo, server = part.rsplit("@", 1)
                decoded = safe_b64decode(b64_userinfo)
                method, password = decoded.split(":", 1)
                host, port = server.split(":")
                return {
                    "type": "shadowsocks",
                    "server": host.strip("[]"),
                    "server_port": int(port),
                    "method": method,
                    "password": password
                }
            else:
                decoded = safe_b64decode(link.split("://")[1])
                method, rest = decoded.split(":", 1)
                password, server = rest.rsplit("@", 1)
                host, port = server.split(":")
                return {
                    "type": "shadowsocks",
                    "server": host.strip("[]"),
                    "server_port": int(port),
                    "method": method,
                    "password": password
                }
        elif link.startswith("vmess://"):
            decoded = safe_b64decode(link.split("://")[1])
            data = json.loads(decoded)
            return {
                "type": "vmess",
                "server": data["add"],
                "server_port": int(data["port"]),
                "uuid": data["id"],
                "security": data.get("scy", "auto"),
                "alterId": int(data.get("aid", 0)),
                "network": data.get("net", "tcp"),
                "tls": {"enabled": data.get("tls", "") == "tls"}
            }
        elif link.startswith("vless://"):
            url = urllib.parse.urlparse(link)
            uuid = url.username
            host = url.hostname
            port = url.port
            params = urllib.parse.parse_qs(url.query)
            outbound = {
                "type": "vless",
                "server": host,
                "server_port": port,
                "uuid": uuid,
                "network": params.get("type", ["tcp"])[0],
                "tls": {"enabled": params.get("security", [""])[0] in ["tls", "reality"]}
            }
            if params.get("security", [""])[0] == "reality":
                outbound["tls"]["reality"] = {
                    "enabled": True,
                    "public_key": params.get("pbk", [""])[0],
                    "short_id": params.get("sid", [""])[0]
                }
                if params.get("sni"):
                    outbound["tls"]["server_name"] = params["sni"][0]
            if params.get("path"):
                outbound["transport"] = {"path": params["path"][0]}
            return outbound
        elif link.startswith("trojan://"):
            url = urllib.parse.urlparse(link)
            password = url.username
            host = url.hostname
            port = url.port
            params = urllib.parse.parse_qs(url.query)
            return {
                "type": "trojan",
                "server": host,
                "server_port": port,
                "password": password,
                "tls": {"enabled": True, "server_name": params.get("sni", [host])[0]}
            }
        elif link.startswith(("hy2://", "hysteria2://")):
            url = urllib.parse.urlparse(link)
            password = url.username
            host = url.hostname
            port = url.port
            return {
                "type": "hysteria2",
                "server": host,
                "server_port": port,
                "password": password,
                "tls": {"enabled": True}
            }
    except Exception:
        return None
    return None

def parse_srs_file(srs_path):
    domains = set()
    cidrs = set()
    try:
        result = subprocess.run(
            ["sing-box", "rule-set", "decompile", srs_path],
            check=True,
            capture_output=True,
            text=True
        )
        data = json.loads(result.stdout)
        for rule in data.get("rules", []):
            domains.update(rule.get("domain_suffix", []))
            domains.update(rule.get("domain", []))
            cidrs.update(rule.get("ip_cidr", []))
    except Exception:
        pass
    return domains, cidrs

def process_srs_url(url, domains_set, cidrs_set=None):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read()
        temp_srs = "temp_rule.srs"
        with open(temp_srs, "wb") as f:
            f.write(content)
        domains, cidrs = parse_srs_file(temp_srs)
        domains_set.update(domains)
        if cidrs_set is not None:
            cidrs_set.update(cidrs)
        if os.path.exists(temp_srs):
            os.remove(temp_srs)
    except Exception:
        pass

def process_rule_source(url, domains_set, cidrs_set=None):
    if url.endswith(".srs"):
        process_srs_url(url, domains_set, cidrs_set)
        return
    
    content = fetch_url(url)
    if not content:
        return
    
    if content.strip().startswith(("{", "[")):
        try:
            data = json.loads(content)
            items = []
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                if "payload" in data:
                    items = data["payload"]
                elif "rules" in data:
                    for rule in data["rules"]:
                        items.extend(rule.get("domain_suffix", []))
                        items.extend(rule.get("domain", []))
                        items.extend(rule.get("ip_cidr", []))
            for item in items:
                if isinstance(item, str):
                    if "/" in item and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+$', item):
                        if cidrs_set is not None:
                            cidrs_set.add(item)
                    else:
                        d = clean_domain(item)
                        if d:
                            domains_set.add(d)
            return
        except Exception:
            pass
    
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!", ";", "//")):
            continue
        
        if cidrs_set is not None and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d+)?$', line.split(',')[0].strip()):
            cidr = line.split(",")[-1].strip()
            cidrs_set.add(cidr)
            continue
        
        d = clean_domain(line)
        if d:
            domains_set.add(d)

def check_domain_via_proxy(domain, proxy_list):
    for proxy in proxy_list[:5]:
        try:
            req = urllib.request.Request(f"http://{domain}", headers={'User-Agent': 'Mozilla/5.0'})
            req.set_proxy(proxy, 'http')
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    return True
        except Exception:
            continue
    return False

def step_collect_proxies():
    print("\n--- 1. СБОР И ФИЛЬТРАЦИЯ ПРОКСИ-УЗЛОВ ---")
    raw_nodes = []
    for source in SOURCES:
        data = fetch_url(source)
        if data:
            for line in data.splitlines():
                line = line.strip()
                if any(line.startswith(proto) for proto in PROTOCOLS):
                    raw_nodes.append(line)
    unique_nodes = list(set(raw_nodes))
    foreign_nodes, ru_nodes = [], []
    for node in unique_nodes:
        if not is_valid_reality(node) or any(bad in node.lower() for bad in BAD_KEYWORDS):
            continue
        host = extract_host(node) or extract_ip_or_domain(node)
        if not host:
            continue
        if check_is_russia(host):
            ru_nodes.append(node)
        else:
            foreign_nodes.append(node)
    if foreign_nodes:
        with open("proxy.txt", "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(sorted(list(set(foreign_nodes)))).encode('utf-8')).decode('utf-8'))
    if ru_nodes:
        with open("ru_proxies.txt", "w", encoding="utf-8") as rf:
            rf.write(base64.b64encode("\n".join(sorted(list(set(ru_nodes)))).encode('utf-8')).decode('utf-8'))
    print(f"Готово! Записано: proxy.txt ({len(foreign_nodes)} нод), ru_proxies.txt ({len(ru_nodes)} нод)")

def step_parse_rules_and_sorting():
    print("\n--- 2. ЗАГРУЗКА И СОРТИРОВКА ПРАВИЛ ИЗ TXT-ФАЙЛОВ ---")
    reject_domains = set()
    reject_cidrs = set()
    direct_domains = set()
    direct_cidrs = set()
    proxy_domains = set()
    proxy_cidrs = set()

    for tg_dom in TELEGRAM_DOMAINS:
        proxy_domains.add(tg_dom)
    for tg_cidr in TELEGRAM_CIDRS:
        proxy_cidrs.add(tg_cidr)
    for wb_cidr in WILDBERRIES_CIDRS:
        proxy_cidrs.add(wb_cidr)

    ru_proxies = []
    if os.path.exists("ru_proxies.txt"):
        with open("ru_proxies.txt", "r", encoding="utf-8") as f:
            ru_b64 = f.read().strip()
            try:
                ru_proxies = base64.b64decode(ru_b64).decode('utf-8').splitlines()
            except Exception:
                ru_proxies = []

    proxy_urls = load_links_from_txt(PROXY_MANUAL_TXT)
    print(f"PROXY: загружено {len(proxy_urls)} ссылок из {PROXY_MANUAL_TXT}")
    for url in proxy_urls:
        print(f"  Обработка: {url}")
        process_rule_source(url, proxy_domains, proxy_cidrs)

    direct_urls = load_links_from_txt(DIRECT_MANUAL_TXT)
    print(f"DIRECT: загружено {len(direct_urls)} ссылок из {DIRECT_MANUAL_TXT}")
    for url in direct_urls:
        print(f"  Обработка: {url}")
        process_rule_source(url, direct_domains, direct_cidrs)

    reject_urls = load_links_from_txt(REJECT_MANUAL_TXT)
    print(f"REJECT: загружено {len(reject_urls)} ссылок из {REJECT_MANUAL_TXT}")
    for url in reject_urls:
        print(f"  Обработка: {url}")
        process_rule_source(url, reject_domains, reject_cidrs)

    dropbox_content = fetch_url(DROPBOX_URL)
    if dropbox_content:
        print("  Обработка Dropbox-логов:")
        for line in dropbox_content.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "!", ";", "//")):
                continue
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d+)?$', line):
                reject_cidrs.add(line.split(",")[-1].strip())
                continue
            d = clean_domain(line)
            if not d:
                continue
            if d in direct_domains or d in proxy_domains:
                print(f"    {d} -> ПРОПУЩЕН (уже в Direct/Proxy)")
                continue
            if is_telegram_domain(d):
                proxy_domains.add(d)
                print(f"    {d} -> в PROXY (Telegram)")
            elif is_domestic_service(d):
                direct_domains.add(d)
                print(f"    {d} -> в DIRECT (РФ-сервис)")
            elif is_ad_or_tracker(d):
                reject_domains.add(d)
                print(f"    {d} -> в REJECT (реклама/трекер)")
            else:
                if ru_proxies and check_domain_via_proxy(d, ru_proxies):
                    direct_domains.add(d)
                    print(f"    {d} -> в DIRECT (доступен через РФ)")
                else:
                    reject_domains.add(d)
                    print(f"    {d} -> в REJECT (неизвестный/недоступный)")

    proxy_domains = {d for d in proxy_domains if d not in reject_domains}
    proxy_cidrs = {c for c in proxy_cidrs if c not in reject_cidrs}
    direct_domains = {d for d in direct_domains if d not in reject_domains}
    direct_cidrs = {c for c in direct_cidrs if c not in reject_cidrs}
    direct_domains = {d for d in direct_domains if d not in proxy_domains}
    direct_cidrs = {c for c in direct_cidrs if c not in proxy_cidrs}

    save_mixed_rules_file(REJECT_JSON, reject_domains, reject_cidrs)
    save_mixed_rules_file(RUS_JSON, direct_domains, direct_cidrs)
    save_mixed_rules_file(PROXY_JSON, proxy_domains, proxy_cidrs)

    print(f"\nСортировка завершена:")
    print(f" -> Реджекты/Реклама: {len(reject_domains)} доменов, {len(reject_cidrs)} CIDR")
    print(f" -> Прямой доступ (Direct): {len(direct_domains)} доменов, {len(direct_cidrs)} CIDR")
    print(f" -> Прокси: {len(proxy_domains)} доменов, {len(proxy_cidrs)} CIDR")

def generate_karing_config():
    print("\n--- 3. ГЕНЕРАЦИЯ KARING_CONFIG.JSON ---")
    proxy_links = []
    if os.path.exists("proxy.txt"):
        with open("proxy.txt", "r", encoding="utf-8") as f:
            proxy_b64 = f.read().strip()
            try:
                proxy_links = base64.b64decode(proxy_b64).decode('utf-8').splitlines()
            except Exception:
                proxy_links = []
    reject_domains = load_json_domains(REJECT_JSON)
    proxy_domains = load_json_domains(PROXY_JSON)
    rus_domains = load_json_domains(RUS_JSON)
    proxy_links = [p for p in proxy_links if p and not any(bad in p.lower() for bad in BAD_KEYWORDS)]

    outbounds = [
        {
            "type": "selector",
            "tag": "Proxy",
            "outbounds": ["auto", "direct"],
            "default": "auto"
        },
        {
            "type": "urltest",
            "tag": "auto",
            "outbounds": [],
            "url": "http://www.gstatic.com/generate_204",
            "interval": "30m",
            "tolerance": 300
        },
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"}
    ]

    auto_outbounds = []
    for i, link in enumerate(proxy_links):
        node = parse_proxy_to_singbox(link)
        if node:
            tag = f"proxy-{i}"
            node["tag"] = tag
            outbounds.append(node)
            auto_outbounds.append(tag)

    outbounds[1]["outbounds"] = auto_outbounds

    rules = [
        {"protocol": ["dns"], "outbound": "dns-out"},
        {"domain_suffix": ["localhost", "local"], "outbound": "direct"},
        {"ip_is_private": True, "outbound": "direct"},
        {"rule_set": "geoip-cn", "outbound": "direct"},
        {"rule_set": "geosite-cn", "outbound": "direct"},
        {"rule_set": "geosite-ad", "outbound": "block"},
        {"domain_suffix": sorted(list(reject_domains)), "outbound": "block"},
        {"domain_suffix": sorted(list(proxy_domains)), "outbound": "Proxy"},
        {"domain_suffix": [".google.com", ".google.ru", ".youtube.com"], "outbound": "Proxy"},
        {"domain_suffix": sorted(list(rus_domains)), "outbound": "direct"},
        {"rule_set": "my_rules_proxy", "outbound": "Proxy"}
    ]

    current_dir = os.path.dirname(os.path.abspath(__file__)) if '__file__' in locals() else os.getcwd()
    rule_set = []

    base_rules = [
        {"tag": "geoip-cn", "url": "https://github.com/SagerNet/sing-geoip/raw/rule-set/geoip-cn.srs"},
        {"tag": "geosite-cn", "url": "https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-cn.srs"},
        {"tag": "geosite-ad", "url": "https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-ad.srs"}
    ]

    for base in base_rules:
        rule_set.append({
            "tag": base["tag"],
            "type": "remote",
            "format": "binary",
            "url": base["url"],
            "download_detour": "direct",
            "update_interval": "24h"
        })

    for json_file in [f for f in os.listdir(current_dir) if f.endswith('.json') and f != "karing_config.json"]:
        srs_file = json_file.replace('.json', '.srs')
        if os.path.exists(os.path.join(current_dir, srs_file)):
            tag = json_file.replace('.json', '')
            rule_set.append({
                "tag": tag,
                "type": "remote",
                "format": "binary",
                "url": f"https://raw.githubusercontent.com/molokokos89-rgb/perturabo-2.1.yaml/refs/heads/main/{srs_file}",
                "download_detour": "direct",
                "update_interval": "2h"
            })

    config = {
        "log": {"level": "info"},
        "dns": {
            "servers": [
                {"tag": "fakeip", "address": "fake-ip", "strategy": "ipv4_only"},
                {"tag": "direct", "address": "77.88.8.8", "address_resolver": "fakeip", "detour": "direct"},
                {"tag": "proxy", "address": "https://dns.google/dns-query", "address_resolver": "fakeip", "detour": "Proxy"}
            ],
            "rules": [
                {"domain_suffix": [".ru", ".su", ".by", ".xn--p1ai"], "server": "direct"},
                {"domain_suffix": [".nalog.ru", ".gosuslugi.ru", ".vk.com", ".yandex.ru", ".mail.ru", ".ok.ru"], "server": "direct"},
                {"server": "fakeip", "query_type": ["A", "AAAA"]}
            ],
            "fakeip": {"enabled": True, "inet4_range": "198.18.0.0/15", "inet6_range": "2001:db8::/32"}
        },
        "inbounds": [
            {"type": "tun", "tag": "tun-in", "interface_name": "utun0", "inet4_address": "172.19.0.1/30", "auto_route": True, "strict_route": True, "sniff": True},
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890}
        ],
        "outbounds": outbounds,
        "route": {
            "rules": rules,
            "rule_set": rule_set,
            "auto_detect_interface": True,
            "final": "Proxy"
        },
        "experimental": {
            "cache_file": {
                "enabled": True,
                "path": "cache.db",
                "store_fakeip": True,
                "store_rdrc": True
            }
        }
    }
    with open("karing_config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    print(f"Готов karing_config.json: {len(auto_outbounds)} прокси, {len(reject_domains)} reject, {len(proxy_domains)} proxy, {len(rus_domains)} direct")

def step_compile_srs():
    print("\n--- 4. КОМПИЛЯЦИЯ В БИНАРНИКИ SING-BOX (.SRS) ---")
    current_dir = os.path.dirname(os.path.abspath(__file__)) if '__file__' in locals() else os.getcwd()
    for jf in [f for f in os.listdir(current_dir) if f.endswith('.json')]:
        if jf == "karing_config.json":
            continue
        srs_file = jf.replace('.json', '.srs')
        if os.path.exists(os.path.join(current_dir, srs_file)):
            os.remove(os.path.join(current_dir, srs_file))
        try:
            subprocess.run(
                ["sing-box", "rule-set", "compile", os.path.join(current_dir, jf), "--output", os.path.join(current_dir, srs_file)],
                check=True,
                capture_output=True,
                text=True
            )
            print(f"Скомпилировано: {jf} -> {srs_file}")
        except Exception as e:
            print(f"Ошибка компиляции {jf}: {e}")

def create_proxy_list_json():
    print("\n--- 5. СОЗДАНИЕ PROXY_LIST.JSON ДЛЯ KARING ---")
    proxy_links = []
    if os.path.exists("proxy.txt"):
        with open("proxy.txt", "r", encoding="utf-8") as f:
            proxy_b64 = f.read().strip()
            try:
                proxy_links = base64.b64decode(proxy_b64).decode('utf-8').splitlines()
            except Exception:
                proxy_links = []
    proxy_links = [p for p in proxy_links if p and not any(bad in p.lower() for bad in BAD_KEYWORDS)]
    working_proxies = []
    print("  Проверка прокси (20 потоков):")

    def check_proxy(link):
        node = parse_proxy_to_singbox(link)
        if not node:
            return None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((node["server"], node["server_port"]))
            sock.close()
            if result == 0:
                return node
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_proxy, link): link for link in proxy_links}
        for future in as_completed(futures):
            node = future.result()
            if node:
                node["tag"] = f"proxy-{len(working_proxies)}"
                working_proxies.append(node)
                print(f"    ✓ {node['server']}:{node['server_port']} - работает")
            else:
                link = futures[future]
                print(f"    ✗ {link[:50]}... - не работает")

    with open("proxy_list.json", "w", encoding="utf-8") as f:
        json.dump(working_proxies, f, indent=2, ensure_ascii=False)
    print(f"Создан proxy_list.json с {len(working_proxies)} рабочими прокси")

def main():
    print("==================================================")
    print("=== СБОРКА ПРАВИЛ ДЛЯ KARING ===")
    print("==================================================")
    step_collect_proxies()
    step_parse_rules_and_sorting()
    generate_karing_config()
    step_compile_srs()
    create_proxy_list_json()
    print("\n==================================================")
    print("=== ГОТОВО! ===")
    print("==================================================")

if __name__ == "__main__":
    main()
