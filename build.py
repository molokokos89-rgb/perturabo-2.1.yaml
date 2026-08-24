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
URLS_FILE = "urls.txt"

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
        req = urllib.request.Request(
            url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
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
        if '@' in clean_link:
            server_part = clean_link.split('@')[-1]
        else:
            server_part = clean_link
        server_address = re.split(r'[:/?#]', server_part)
        return server_address[0].strip()
    except Exception:
        return None

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
            return host_port.split(":")[0].strip("[]")
        elif line.startswith(("trojan://", "hy2://", "hysteria2://", "vless://", "tuic://")):
            if "@" in line:
                part = line.split("://")[1].split("@")[1]
                return part.split(":")[0].split("?")[0].strip("[]")
            else:
                part = line.split("://")[1]
                return part.split(":")[0].split("?")[0].strip("[]")
        elif line.startswith("vmess://"):
            b64_str = line.split("://")[1].split("?")[0]
            decoded = safe_b64decode(b64_str)
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
        banned_sni_keywords = ["google", "netflix", "facebook", "instagram", "twitter", "youtube"]
        if any(keyword in sni for keyword in banned_sni_keywords):
            return False
    return True

def check_is_russia(host):
    if not host:
        return False
    if host.lower().endswith('.ru') or host.lower().endswith('.su') or host.lower().endswith('.by'):
        return True
    try:
        try:
            socket.inet_aton(host)
            ip = host
        except socket.error:
            ip = socket.gethostbyname(host)
            
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
    if not line or line.startswith(("#", "!", ";", "//")):
        return None
    line = re.sub(r'^(127\.0\.0\.1|0\.0\.0\.0)\s+', '', line)
    if "#" in line:
        line = line.split("#")[0]
    line = line.strip()
    line = re.sub(r'^[a-z0-9]+://', '', line)
    line = line.split('/')[0].split('?')[0].split(':')[0]
    if line.startswith("||"): line = line[2:]
    if line.endswith("^"): line = line[:-1]
    line = line.strip(".-").replace("*.", "")
    if re.search(r'\.(js|css|png|jpg|jpeg|svg|gif|woff|woff2|json)$', line):
        return None
    if len(line) > 65:
        return None
    domain_regex = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
    if re.match(domain_regex, line):
        if not any(line.startswith(ip) for ip in ["127.", "0.", "192.168.", "10."]):
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
                    if cd: domains.add(cd)
        except Exception:
            pass
    return domains

def save_mixed_rules_file(filename, domains, cidrs):
    sorted_domains = sorted(list(set(domains)))
    sorted_cidrs = sorted(list(set(cidrs)))
    rule_obj = {}
    if sorted_domains:
        rule_obj["domain_suffix"] = sorted_domains
    if sorted_cidrs:
        rule_obj["ip_cidr"] = sorted_cidrs
    data = {
        "version": 1,
        "payload": sorted_domains + sorted_cidrs,
        "rules": [rule_obj] if rule_obj else []
    }
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def step_collect_proxies():
    print("\n--- 1. СБОР И ФИЛЬТРАЦИЯ ПРОКСИ-УЗЛОВ (ИЗ ВАШЕГО РЕПО) ---")
    raw_nodes = []
    for source in SOURCES:
        data = fetch_url(source)
        if data:
            for line in data.splitlines():
                line = line.strip()
                if any(line.startswith(proto) for proto in PROTOCOLS):
                    raw_nodes.append(line)
                    
    unique_nodes = list(set(raw_nodes))
    foreign_nodes = []
    ru_nodes = []
    
    for node in unique_nodes:
        if not is_valid_reality(node):
            continue
        if any(bad in node.lower() for bad in BAD_KEYWORDS):
            continue
            
        host = extract_host(node)
        if not host:
            host = extract_ip_or_domain(node)
            
        if check_is_russia(host):
            ru_nodes.append(node)
        else:
            foreign_nodes.append(node)
            
    if foreign_nodes:
        raw_text = "\n".join(sorted(list(set(foreign_nodes))))
        b64_output = base64.b64encode(raw_text.encode('utf-8')).decode('utf-8')
        with open("proxy.txt", "w", encoding="utf-8") as f:
            f.write(b64_output)
            
    if ru_nodes:
        ru_raw_text = "\n".join(sorted(list(set(ru_nodes))))
        ru_b64 = base64.b64encode(ru_raw_text.encode('utf-8')).decode('utf-8')
        with open("ru_proxies.txt", "w", encoding="utf-8") as rf:
            rf.write(ru_b64)

    print(f"Готово! Записано: proxy.txt ({len(foreign_nodes)} нод), ru_proxies.txt ({len(ru_nodes)} нод)")

def step_parse_rules_and_logs():
    print("\n--- 2. СБОР ПРАВИЛ REJECT, PROXY И ЛОГОВ (DROPBOX) ---")
    rejected_domains = load_json_domains(REJECT_JSON)
    rejected_cidrs = set()
    
    proxy_domains = load_json_domains(PROXY_JSON)
    proxy_cidrs = set()
    
    rus_domains = load_json_domains(RUS_JSON)
    rus_cidrs = set()

    for tg_dom in TELEGRAM_DOMAINS:
        proxy_domains.add(tg_dom)

    for key, url in RULE_SOURCES.items():
        content = fetch_url(url)
        if content:
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith(("#", "!", ";", "//")):
                    continue
                if "/" in line or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line.split(',')[0].strip()):
                    clean_ip = line.split(",")[-1].strip()
                    if key in ["telegram"]:
                        proxy_cidrs.add(clean_ip)
                    continue
                d = clean_domain(line)
                if d:
                    if is_telegram_domain(d):
                        proxy_domains.add(d)
                    elif key in ["reject", "adguard_dns", "adguard_trackers", "oisd_small", "stevenblack"] or is_ad_or_tracker(d):
                        rejected_domains.add(d)
                    elif key in ["telegram", "youtube", "tiktok", "proxy_media", "google", "apple"]:
                        proxy_domains.add(d)

    dropbox_content = fetch_url(DROPBOX_URL)
    if dropbox_content:
        for line in dropbox_content.splitlines():
            line = line.strip()
            if "/" in line or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
                proxy_cidrs.add(line)
                continue
            d = clean_domain(line)
            if d:
                if is_telegram_domain(d):
                    proxy_domains.add(d)
                elif is_domestic_service(d):
                    rus_domains.add(d)
                else:
                    rejected_domains.add(d)

    save_mixed_rules_file(REJECT_JSON, rejected_domains, rejected_cidrs)
    save_mixed_rules_file(PROXY_JSON, proxy_domains, proxy_cidrs)
    save_mixed_rules_file(RUS_JSON, rus_domains, rus_cidrs)

def step_check_heavy_rkn():
    print("\n--- 3. ПРОВЕРКА БАЗ РКН И URLS.TXT В 20 ПОТОКОВ ---")
    existing_proxies = load_json_domains(PROXY_JSON)
    existing_rejects = load_json_domains(REJECT_JSON)
    heavy_domains = set()

    for url in HEAVY_SOURCES:
        content = fetch_url(url)
        if content:
            for line in content.splitlines():
                d = clean_domain(line)
                if d and not is_domestic_service(d):
                    if d not in existing_proxies and d not in existing_rejects:
                        heavy_domains.add(d)

    if os.path.exists(URLS_FILE):
        with open(URLS_FILE, "r", encoding="utf-8") as f:
            urls = [l.strip() for l in f if l.strip()]
        for idx, url in enumerate(urls):
            srs_file = f"temp_{idx}.srs"
            json_file = f"temp_{idx}.json"
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=15) as res:
                    content = res.read()
                    if url.endswith(".srs"):
                        with open(srs_file, "wb") as out: out.write(content)
                        subprocess.run(["sing-box", "rule-set", "decompile", srs_file, "--output", json_file], check=True)
                        with open(json_file, "r", encoding="utf-8") as jf:
                            data = json.load(jf)
                        for rule in data.get("rules", []):
                            for key in ["domain", "domain_suffix"]:
                                for d in rule.get(key, []):
                                    cd = clean_domain(d)
                                    if cd and not is_domestic_service(cd): heavy_domains.add(cd)
                    else:
                        for line in content.decode('utf-8', errors='ignore').splitlines():
                            cd = clean_domain(line.split(",")[-1] if "," in line else line)
                            if cd and not is_domestic_service(cd): heavy_domains.add(cd)
            except Exception:
                pass
            finally:
                if os.path.exists(srs_file): os.remove(srs_file)
                if os.path.exists(json_file): os.remove(json_file)

    def test_domain(domain):
        try:
            req = urllib.request.Request(f"https://{domain}", headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=3) as res:
                html = res.read().decode('utf-8', errors='ignore').lower()
                if any(w in html for w in ["заблокирован", "роскомнадзор", "block", "deny"]):
                    return domain, True
                return domain, False
        except Exception:
            return domain, True

    blocked, allowed = [], []
    if heavy_domains:
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(test_domain, d): d for d in heavy_domains}
            for future in as_completed(futures):
                d, is_blocked = future.result()
                if is_blocked: blocked.append(d)
                else: allowed.append(d)

    save_mixed_rules_file("blocked.json", blocked, set())
    save_mixed_rules_file("allowed.json", allowed, set())

def step_global_cleaner():
    print("\n--- 4. ГЛОБАЛЬНАЯ ОЧИСТКА ПЕРЕСЕЧЕНИЙ ---")
    proxy_set = load_json_domains(PROXY_JSON)
    rus_set = load_json_domains(RUS_JSON)
    reject_set = load_json_domains(REJECT_JSON)

    for tg_dom in TELEGRAM_DOMAINS:
        proxy_set.add(tg_dom)

    proxy_clean = set()
    for d in proxy_set:
        if is_telegram_domain(d):
            proxy_clean.add(d)
        elif not is_domestic_service(d) and not is_ad_or_tracker(d):
            proxy_clean.add(d)
        elif is_domestic_service(d):
            rus_set.add(d)

    for d in proxy_clean:
        reject_set.discard(d)
        rus_set.discard(d)
    for d in rus_set:
        reject_set.discard(d)

    save_mixed_rules_file(PROXY_JSON, proxy_clean, set())
    save_mixed_rules_file(RUS_JSON, rus_set, set())
    save_mixed_rules_file(REJECT_JSON, reject_set, set())

def step_compile_srs():
    print("\n--- 5. КОМПИЛЯЦИЯ В БИНАРНИКИ SING-BOX (.SRS) ---")
    current_dir = os.path.dirname(os.path.abspath(__file__)) if '__file__' in locals() else os.getcwd()
    json_files = [f for f in os.listdir(current_dir) if f.endswith('.json')]
    
    for jf in json_files:
        srs_file = jf.replace('.json', '.srs')
        json_path = os.path.join(current_dir, jf)
        srs_path = os.path.join(current_dir, srs_file)
        try:
            result = subprocess.run(
                ["sing-box", "rule-set", "compile", json_path, "--output", srs_path],
                check=True,
                capture_output=True,
                text=True
            )
            print(f"Успешно скомпилировано: {jf} -> {srs_file}")
        except subprocess.CalledProcessError as e:
            print(f"ОШИБКА компиляции файла {jf}:")
            print(e.stderr)
        except Exception as e:
            print(f"Непредвиденная ошибка для {jf}: {e}")

def main():
    print("==================================================")
    print("=== ЗАПУСК ПОЛНОГО ЦИКЛА СБОРКИ ПРАВИЛ И НОД ===")
    print("==================================================")
    
    step_collect_proxies()
    step_parse_rules_and_logs()
    step_check_heavy_rkn()
    step_global_cleaner()
    step_compile_srs()

    print("\n==================================================")
    print("=== ВСЕ ЭТАПЫ СБОРКИ УСПЕШНО ЗАВЕРШЕНЫ! ===")
    print("==================================================")

if __name__ == "__main__":
    main()

