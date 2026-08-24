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

SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS%2BAll_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/hy2.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt"
]

DROPBOX_URL = "https://www.dropbox.com/scl/fi/759t1a2us3y0kblgat0xr/log-for-reject.txt?rlkey=zr2uqv81lx89rdl6q55geyucy&st=8lc13ygu&dl=1"

PROTOCOLS = ["ss://", "vmess://", "trojan://", "hy2://", "hysteria2://", "vless://"]
BAD_KEYWORDS = ["russia", "anycast", "fixnet", "fixcord", "cloudflare", "warp", "cf-"]

TELEGRAM_DOMAINS = [
    "t.me", "telegram.org", "telegram.me", "tdesktop.com", "telegra.ph", 
    "telegram.dog", "tx.me", "usercontent.dev"
]

TELEGRAM_CIDRS = [
    "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22",
    "91.108.20.0/22", "91.108.56.0/22", "149.154.160.0/20", "149.154.164.0/22",
    "149.154.168.0/22", "149.154.172.0/22", "185.76.151.0/24", "200.1.1.0/24"
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
    "vk.ru", "mail.ru", "ok.ru", "rutube", "gosuslugi", "sberbank", "tbank", "tinkoff"
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
    sorted_domains = sorted(list(set(domains)))
    sorted_cidrs = sorted(list(set(cidrs)))
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
    proxy_urls = load_links_from_txt(PROXY_MANUAL_TXT)
    print(f"PROXY: {len(proxy_urls)} ссылок")
    for url in proxy_urls:
        process_url_content(url, proxy_domains, proxy_cidrs)
    direct_urls = load_links_from_txt(DIRECT_MANUAL_TXT)
    print(f"DIRECT: {len(direct_urls)} ссылок")
    for url in direct_urls:
        process_url_content(url, direct_domains, direct_cidrs)
    reject_urls = load_links_from_txt(REJECT_MANUAL_TXT)
    print(f"REJECT: {len(reject_urls)} ссылок")
    for url in reject_urls:
        process_url_content(url, reject_domains, reject_cidrs)
    dropbox_content = fetch_url(DROPBOX_URL)
    if dropbox_content:
        for line in dropbox_content.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "!", ";", "//")):
                continue
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d+)?$', line):
                reject_cidrs.add(line.split(",")[-1].strip())
                continue
            d = clean_domain(line)
            if d:
                if is_telegram_domain(d):
                    proxy_domains.add(d)
                elif is_ad_or_tracker(d):
                    reject_domains.add(d)
                elif is_domestic_service(d):
                    direct_domains.add(d)
                else:
                    reject_domains.add(d)
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
    outbounds = [
        {"type": "selector", "tag": "proxy", "outbounds": ["auto"], "default": "auto"},
        {"type": "urltest", "tag": "auto", "outbounds": [], "url": "http://www.gstatic.com/generate_204", "interval": "5m"},
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"}
    ]
    auto_outbounds = []
    for i, link in enumerate(proxy_links):
        node = parse_proxy_to_singbox(link)
        if node:
            tag = f"node-{i}"
            node["tag"] = tag
            outbounds.append(node)
            auto_outbounds.append(tag)
    outbounds[1]["outbounds"] = auto_outbounds
    rules = [
        {"domain_suffix": sorted(list(reject_domains)), "outbound": "block"},
        {"domain_suffix": sorted(list(proxy_domains)), "outbound": "proxy"},
        {"domain_suffix": sorted(list(rus_domains)), "outbound": "direct"},
        {"protocol": ["dns"], "outbound": "direct"}
    ]
    config = {
        "log": {"level": "error"},
        "inbounds": [
            {"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"], "auto_route": True, "strict_route": True}
        ],
        "outbounds": outbounds,
        "route": {
            "rules": rules,
            "final": "proxy"
        }
    }
    with open("karing_config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    print(f"Готов karing_config.json: {len(proxy_links)} прокси, {len(reject_domains)} reject, {len(proxy_domains)} proxy, {len(rus_domains)} direct")

def step_compile_srs():
    print("\n--- 4. КОМПИЛЯЦИЯ В БИНАРНИКИ SING-BOX (.SRS) ---")
    current_dir = os.path.dirname(os.path.abspath(__file__)) if '__file__' in locals() else os.getcwd()
    for jf in [f for f in os.listdir(current_dir) if f.endswith('.json')]:
        srs_file = jf.replace('.json', '.srs')
        try:
            subprocess.run(["sing-box", "rule-set", "compile", os.path.join(current_dir, jf), "--output", os.path.join(current_dir, srs_file)], check=True, capture_output=True, text=True)
            print(f"Скомпилировано: {jf} -> {srs_file}")
        except Exception as e:
            print(f"Ошибка компиляции {jf}: {e}")

def main():
    print("==================================================")
    print("=== СБОРКА ПРАВИЛ ДЛЯ KARING ===")
    print("==================================================")
    step_collect_proxies()
    step_parse_rules_and_sorting()
    generate_karing_config()
    step_compile_srs()
    print("\n==================================================")
    print("=== ГОТОВО! ===")
    print("==================================================")

if __name__ == "__main__":
    main()