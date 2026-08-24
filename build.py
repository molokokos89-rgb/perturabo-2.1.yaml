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

# ==========================================
# 1. КОНФИГУРАЦИЯ И ФАЙЛЫ-ИСТОЧНИКИ (TXT)
# ==========================================
RUS_JSON = "My_rules_RUS.json"
REJECT_JSON = "reject_rules.json"
PROXY_JSON = "my_rules_proxy.json"

# Текстовые файлы, куда вы будете просто дописывать ссылки
PROXY_SOURCES_TXT = "proxy_sources.txt"
DIRECT_SOURCES_TXT = "direct_sources.txt"
REJECT_SOURCES_TXT = "reject_sources.txt"

# Источники для нод (их оставляем в коде, так как это техническая база)
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

# ==========================================
# 2. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ==========================================

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

def load_links_from_txt(filename):
    """Читает список URL-адресов из текстового файла"""
    urls = []
    if os.path.exists(filename):
        with open(filename, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith(("#", "//")):
                    urls.append(line)
    return urls

def process_url_content(url, domains_set, cidrs_set=None):
    """Скачивает контент по ссылке и парсит из него домены или CIDR"""
    content = fetch_url(url)
    if not content:
        return
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!", ";", "//")):
            continue
        if ("/" in line or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line.split(',')[0].strip())) and cidrs_set is not None:
            clean_ip = line.split(",")[-1].strip()
            cidrs_set.add(clean_ip)
            continue
        d = clean_domain(line)
        if d:
            domains_set.add(d)

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

# ==========================================
# 3. ОСНОВНЫЕ ЭТАПЫ СБОРКИ
# ==========================================

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
    print("\n--- 2. ЗАГРУЗКА И СОРТИРОВКА ПРАВИЛ ИЗ TXT-ФАЙЛОВ С ССЫЛКАМИ ---")
    
    reject_domains = set()
    direct_domains = set()
    proxy_domains = set()
    proxy_cidrs = set()

    # Всегда держим Telegram в прокси
    for tg_dom in TELEGRAM_DOMAINS:
        proxy_domains.add(tg_dom)

    # 1. Загружаем Proxy-ссылки из файла proxy_sources.txt
    proxy_urls = load_links_from_txt(PROXY_SOURCES_TXT)
    print(f"Найдено ссылок для PROXY: {len(proxy_urls)}")
    for url in proxy_urls:
        process_url_content(url, proxy_domains, proxy_cidrs)

    # 2. Загружаем Direct-ссылки из файла direct_sources.txt
    direct_urls = load_links_from_txt(DIRECT_SOURCES_TXT)
    print(f"Найдено ссылок для DIRECT: {len(direct_urls)}")
    for url in direct_urls:
        process_url_content(url, direct_domains)

    # 3. Загружаем Reject-ссылки из файла reject_sources.txt
    reject_urls = load_links_from_txt(REJECT_SOURCES_TXT)
    print(f"Найдено ссылок для REJECT: {len(reject_urls)}")
    for url in reject_urls:
        process_url_content(url, reject_domains)

    # 4. Подтягиваем логи из Dropbox в Reject (если они нужны)
    dropbox_content = fetch_url(DROPBOX_URL)
    if dropbox_content:
        for line in dropbox_content.splitlines():
            d = clean_domain(line)
            if d:
                reject_domains.add(d)

    # Жесткое разделение и очистка пересечений (Приоритет: Reject > Direct > Proxy)
    direct_domains = {d for d in direct_domains if d not in reject_domains}
    proxy_domains = {d for d in proxy_domains if d not in reject_domains and d not in direct_domains}

    save_mixed_rules_file(REJECT_JSON, reject_domains, set())
    save_mixed_rules_file(RUS_JSON, direct_domains, set())
    save_mixed_rules_file(PROXY_JSON, proxy_domains, proxy_cidrs)
    
    print(f"Сортировка завершена:")
    print(f" -> Реджекты/Реклама: {len(reject_domains)}")
    print(f" -> Прямой доступ (Direct): {len(direct_domains)}")
    print(f" -> Прокси: {len(proxy_domains)}")

def step_compile_srs():
    print("\n--- 3. КОМПИЛЯЦИЯ В БИНАРНИКИ SING-BOX (.SRS) ---")
    current_dir = os.path.dirname(os.path.abspath(__file__)) if '__file__' in locals() else os.getcwd()
    for jf in [f for f in os.listdir(current_dir) if f.endswith('.json')]:
        srs_file = jf.replace('.json', '.srs')
        try:
            subprocess.run(["sing-box", "rule-set", "compile", os.path.join(current_dir, jf), "--output", os.path.join(current_dir, srs_file)], check=True, capture_output=True, text=True)
            print(f"Скомпилировано: {jf} -> {srs_file}")
        except Exception as e:
            print(f"Ошибка компиляции {jf}: {e}")

# ==========================================
# 4. ГЛАВНАЯ ТОЧКА ВХОДА
# ==========================================
def main():
    print("==================================================")
    print("=== СБОРКА С ЧТЕНИЕМ ССЫЛОК ИЗ TXT-ФАЙЛОВ ===")
    print("==================================================")
    step_collect_proxies()
    step_parse_rules_and_sorting()
    step_compile_srs()
    print("==================================================")
    print("=== ГОТОВО! ===")
    print("==================================================")

if __name__ == "__main__":
    main()