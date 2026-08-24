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
# 1. КОНФИГУРАЦИЯ И ФАЙЛЫ
# ==========================================
RUS_JSON = "My_rules_RUS.json"
REJECT_JSON = "reject_rules.json"
PROXY_JSON = "my_rules_proxy.json"

# Новые ручные файлы-списки
REJECT_TXT = "reject_manual.txt"
DIRECT_TXT = "direct_manual.txt"
PROXY_TXT = "proxy_manual.txt"
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

# Доверенные базы для автодополнения (можно сократить при желании)
RULE_SOURCES = {
    "telegram": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/telegramcidr.txt",
    "google": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/google.txt",
    "youtube": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/youtube.txt",
    "reject": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt",
}

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

def load_txt_file(filename):
    domains = set()
    if os.path.exists(filename):
        with open(filename, "r", encoding="utf-8") as f:
            for line in f:
                cd = clean_domain(line)
                if cd:
                    domains.add(cd)
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

# ==========================================
# 3. ОСНОВНЫЕ ЭТАПЫ
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
    print("\n--- 2. СБОР И СТРОГАЯ СОРТИРОВКА ПО РУЧНЫМ СПИСКАМ ---")
    
    # 1. Загружаем пользовательские базы из TXT
    reject_domains = load_txt_file(REJECT_TXT)
    direct_domains = load_txt_file(DIRECT_TXT)
    proxy_domains = load_txt_file(PROXY_TXT)
    
    proxy_cidrs = set()

    # Всегда держим Telegram в прокси
    for tg_dom in TELEGRAM_DOMAINS:
        proxy_domains.add(tg_dom)

    # 2. Докачиваем базовые списки (Telegram CIDR и стандартный Reject)
    for key, url in RULE_SOURCES.items():
        content = fetch_url(url)
        if content:
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith(("#", "!", ";", "//")):
                    continue
                if "/" in line or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line.split(',')[0].strip()):
                    clean_ip = line.split(",")[-1].strip()
                    if key == "telegram":
                        proxy_cidrs.add(clean_ip)
                    continue
                d = clean_domain(line)
                if d:
                    if key == "reject":
                        reject_domains.add(d)
                    elif key == "telegram":
                        proxy_domains.add(d)

    # 3. Подтягиваем логи из Dropbox в Reject
    dropbox_content = fetch_url(DROPBOX_URL)
    if dropbox_content:
        for line in dropbox_content.splitlines():
            d = clean_domain(line)
            if d:
                reject_domains.add(d)

    # 4. Жесткий приоритет и очистка пересечений (Reject > Direct > Proxy)
    direct_domains = {d for d in direct_domains if d not in reject_domains}
    proxy_domains = {d for d in proxy_domains if d not in reject_domains and d not in direct_domains}

    # Сохраняем в JSON для sing-box
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

def main():
    print("==================================================")
    print("=== СБОРКА НА БАЗЕ РУЧНЫХ СПИСКОВ (TXT) ===")
    print("==================================================")
    step_collect_proxies()
    step_parse_rules_and_sorting()
    step_compile_srs()
    print("==================================================")
    print("=== ГОТОВО! ===")
    print("==================================================")

if __name__ == "__main__":
    main()