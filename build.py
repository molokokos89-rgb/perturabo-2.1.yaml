import urllib.request
import re
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==========================================
# 1. ПУТИ К ИТОГОВЫМ JSON-ФАЙЛАМ
# ==========================================
RUS_JSON = "My_rules_RUS.json"
REJECT_JSON = "reject_rules.json"
PROXY_JSON = "my_rules_proxy.json"

# Внешняя ссылка на личный лог блокировок
DROPBOX_URL = "https://www.dropbox.com/scl/fi/759t1a2us3y0kblgat0xr/log-for-reject.txt?rlkey=zr2uqv81lx89rdl6q55geyucy&st=8lc13ygu&dl=1"

# Ссылки на основные файлы репозитория
MAIN_REPO_RULES = {
    "rus": "https://raw.githubusercontent.com/molokokos89-rgb/perturabo-2.0.yaml/refs/heads/main/My_rules_RUS.json",
    "proxy": "https://raw.githubusercontent.com/molokokos89-rgb/perturabo-2.0.yaml/refs/heads/main/my_rules_proxy.json",
    "reject": "https://raw.githubusercontent.com/molokokos89-rgb/perturabo-2.0.yaml/refs/heads/main/reject_rules.json"
}

# Источники категорий правил (Loyalsoldier и др.)
RULE_SOURCES = {
    "telegram": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/telegramcidr.txt",
    "google": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/google.txt",
    "apple": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/apple.txt",
    "youtube": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/youtube.txt",
    "tiktok": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/tiktok.txt",
    "proxy_media": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt",
    "reject": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt"
}

# Тяжелая база заблокированных доменов (Роскомсвобода / Роскомкод)
HEAVY_SOURCES = [
    "https://raw.githubusercontent.com/roskomkod/ru-blocked-domains/main/domains.txt"
]

# Ключевые слова для мгновенного определения рекламных доменов и трекеров
AD_TRACKER_KEYWORDS = [
    "analytics", "ads", "pixel", "metrics", "telemetry", "tracker",
    "tracking", "adservice", "adsystem", "banner", "counter", "pangle",
    "bdtone", "doubleclick", "app-measurement", "adjust", "appsflyer"
]

# Белый список доменов (их нельзя отправлять в reject целиком)
WHITELIST_EXACT = [
    "tiktok.com", "facebook.com", "rutube.ru", "youtube.com", "vk.com",
    "t.me", "telegram.org", "instagram.com"
]

# Регулярные выражения белого списка
WHITELIST_PATTERNS = [
    r"^([^.]+\.)*tiktok\.com$",
    r"^([^.]+\.)*facebook\.com$",
    r"^([^.]+\.)*rutube\.ru$",
    r"^([^.]+\.)*googlevideo\.com$"
]

# ==========================================
# 2. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ФИЛЬТРАЦИИ
# ==========================================

def is_ad_or_tracker(domain):
    """Проверяет, содержит ли домен рекламные ключевые слова"""
    domain_lower = domain.lower()
    return any(keyword in domain_lower for keyword in AD_TRACKER_KEYWORDS)

def is_dangerous_block(domain):
    """Проверяет, не входит ли домен в белый список важных сервисов"""
    if domain in WHITELIST_EXACT:
        return True
    for pattern in WHITELIST_PATTERNS:
        if re.match(pattern, domain):
            # Если это рекламный поддомен в важном сервисе — блокировать можно
            if is_ad_or_tracker(domain):
                return False
            return True
    return False

def clean_domain(line):
    """Универсальная очистка доменов от комментариев, IP-адресов и AdGuard-синтаксиса"""
    line = line.strip().lower()
    if not line or line.startswith(("#", "!", ";", "//")):
        return None
    
    # Очищаем от формата hosts (127.0.0.1 или 0.0.0.0)
    line = re.sub(r'^(127\.0\.0\.1|0\.0\.0\.0)\s+', '', line)
    
    # Отрезаем комментарии в конце строки
    if "#" in line:
        line = line.split("#")[0]
    line = line.strip()
    
    # Убираем протоколы, пути и порты
    line = re.sub(r'^[a-z0-9]+://', '', line)
    line = line.split('/')[0].split('?')[0].split(':')[0]
    
    # Очищаем спецсимволы AdGuard/uBlock (|| domain.com ^)
    if line.startswith("||"):
        line = line[2:]
    if line.endswith("^"):
        line = line[:-1]
        
    line = line.strip(".-")
    
    # Проверка на валидность имени домена
    domain_regex = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
    if re.match(domain_regex, line):
        return line
        
    return None

def download_text(url):
    """Безопасно скачивает текстовый файл по URL"""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.read().decode('utf-8', errors='ignore')
    except Exception:
        return ""

def load_existing_proxy_domains():
    """Загружает уже имеющиеся прокси-домены из my_rules_proxy.json"""
    domains = set()
    if os.path.exists(PROXY_JSON):
        try:
            with open(PROXY_JSON, "r", encoding="utf-8") as f:
                data = json.load(f)
                # Поддержка стандартной структуры payload и классической rules
                items = data.get("payload", [])
                if not items and "rules" in data:
                    for rule in data.get("rules", []):
                        items.extend(rule.get("domain_suffix", []))
                
                for d in items:
                    cleaned = clean_domain(d)
                    if cleaned and not is_ad_or_tracker(cleaned):
                        domains.add(cleaned)
        except Exception:
            pass
    return domains

# ==========================================
# 3. ПРОВЕРКА ДОСТУПНОСТИ ДОМЕНОВ (МНОГОПОТОЧНОСТЬ)
# ==========================================

def test_single_domain(domain):
    """Проверяет доступность одного домена (ищет заглушки блокировок РКН)"""
    try:
        req = urllib.request.Request(f"https://{domain}", headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as res:
            html = res.read().decode('utf-8', errors='ignore').lower()
            if any(w in html for w in ["заблокирован", "роскомнадзор", "block", "deny"]):
                return domain, True
            return domain, False
    except Exception:
        # Если соединение сброшено или таймаут — считаем заблокированным
        return domain, True

def check_domains_availability(domains_set):
    """Проверяет массив доменов в 20 параллельных потоков"""
    blocked = []
    allowed = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(test_single_domain, d): d for d in domains_set}
        for future in as_completed(futures):
            domain, is_blocked = future.result()
            if is_blocked:
                blocked.append(domain)
            else:
                allowed.append(domain)
    return sorted(blocked), sorted(allowed)

# ==========================================
# 4. ОСНОВНОЙ ПРОЦЕСС СБОРКИ
# ==========================================

def save_rules_file(filename, domain_list):
    """Сохраняет итоговый список с поддержкой обоих форматов (payload и rules)"""
    data = {
        "version": 1,
        "payload": domain_list,
        "rules": [{"domain_suffix": domain_list}]
    }
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def main():
    print("=== ЗАПУСК СБОРКИ ПРАВИЛ REJECT И ПРОВЕРКИ РКН ===")
    rejected_domains = set()
    
    # 1. Загрузка старых правил из reject_rules.json
    if os.path.exists("reject_rules.json"):
        try:
            with open("reject_rules.json", "r", encoding="utf-8") as f:
                old_data = json.load(f)
                items = old_data.get("payload", [])
                if not items and "rules" in old_data:
                    for rule in old_data.get("rules", []):
                        items.extend(rule.get("domain_suffix", []))
                for d in items:
                    cd = clean_domain(d)
                    if cd:
                        rejected_domains.add(cd)
        except Exception:
            pass

    # 2. Скачивание основных списков (Telegram, Google, YouTube, Reject)
    for key, url in RULE_SOURCES.items():
        content = download_text(url)
        if content:
            for line in content.splitlines():
                domain = clean_domain(line)
                if domain:
                    if key == "reject" or is_ad_or_tracker(domain):
                        rejected_domains.add(domain)

    # 3. Скачивание персонального лога с Dropbox
    dropbox_content = download_text(DROPBOX_URL)
    if dropbox_content:
        for line in dropbox_content.splitlines():
            cd = clean_domain(line)
            if cd and not cd.startswith(("127.", "0.", "192.168.", "10.")):
                rejected_domains.add(cd)

    # 4. Исключаем из reject те домены, которые должны идти через прокси
    existing_proxies = load_existing_proxy_domains()
    for d in existing_proxies:
        rejected_domains.discard(d)

    # Сохраняем промежуточный результат reject_rules.json
    save_rules_file("reject_rules.json", sorted(list(rejected_domains)))

    # 5. Обработка тяжелых баз РКН (roskomkod)
    collected_heavy = set()
    for url in HEAVY_SOURCES:
        content = download_text(url)
        if content:
            for line in content.splitlines():
                rd = clean_domain(line)
                if rd and len(rd) > 3:
                    if is_ad_or_tracker(rd):
                        rejected_domains.add(rd)
                        continue
                    if rd not in existing_proxies and rd not in rejected_domains:
                        # Не проверяем российские и СНГ доменные зоны
                        if not any(rd.endswith(zone) for zone in [".ru", ".su", ".by", ".xn--p1ai"]):
                            collected_heavy.add(rd)

    # Пересохраняем обновленный reject_rules.json после обработки тяжелых баз
    save_rules_file("reject_rules.json", sorted(list(rejected_domains)))

    # 6. Проверка доступности собранных доменов РКН в 20 потоков
    if collected_heavy:
        print(f"Проверка {len(collected_heavy)} доменов из баз РКН на доступность...")
        blocked_list, allowed_list = check_domains_availability(collected_heavy)
        
        save_rules_file("blocked.json", blocked_list)
        save_rules_file("allowed.json", allowed_list)
        print(f"Завершено: {len(blocked_list)} заблокировано, {len(allowed_list)} доступно.")

    print("=== СБОРКА И ПРОВЕРКА УСПЕШНО ЗАВЕРШЕНА ===")

if __name__ == "__main__":
    main()