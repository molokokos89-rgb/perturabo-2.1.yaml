import sys
import re
import json
import base64
import urllib.request
import urllib.parse
import subprocess
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

def safe_b64decode(data):
    data = data.strip()
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.b64decode(data).decode('utf-8', errors='ignore')

def test_single_domain(domain):
    """Проверка доступности домена с сервера"""
    try:
        req = urllib.request.Request(f"https://{domain}", headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as res:
            html = res.read().decode('utf-8', errors='ignore').lower()
            if any(w in html for w in ["заблокирован", "роскомнадзор", "block", "deny"]):
                return domain, True
            return domain, False
    except Exception:
        # Если порт сброшен или сайт не отвечает — считаем заблокированным в РФ
        return domain, True

def load_domains_from_sources():
    """Скачивает и разбирает файлы правил из urls.txt (.txt, .json, .srs)"""
    if not os.path.exists("urls.txt"):
        return []
    with open("urls.txt", "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]
    
    all_extracted = []
    for index, url in enumerate(urls):
        srs_file = f"temp_{index}.srs"
        json_file = f"temp_{index}.json"
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as response:
                content = response.read()
                
                if url.endswith(".json"):
                    data = json.loads(content.decode('utf-8'))
                    if "payload" in data: 
                        all_extracted.extend(data["payload"])
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
                    with open(srs_file, "wb") as out: 
                        out.write(content)
                    subprocess.run(["sing-box", "rule-set", "decompile", srs_file, "--output", json_file], check=True)
                    with open(json_file, "r", encoding="utf-8") as jf:
                        data = json.load(jf)
                    for rule in data.get("rules", []):
                        if "domain" in rule: all_extracted.extend(rule["domain"])
                        if "domain_suffix" in rule: all_extracted.extend(rule["domain_suffix"])
        except Exception as e:
            print(f"Ошибка при обработке {url}: {e}")
        finally:
            if os.path.exists(srs_file): os.remove(srs_file)
            if os.path.exists(json_file): os.remove(json_file)

    clean_domains = []
    for d in all_extracted:
        d_clean = d.strip().split(",")[-1] if "," in d else d.strip()
        if d_clean and not d_clean.startswith("+."):
            clean_domains.append(d_clean.replace("*.", ""))
    return list(set(clean_domains))

def save_rules_file(filename, domain_list):
    """Универсальное сохранение для Clash/Karing/Mihomo"""
    data = {
        "version": 1,
        "payload": domain_list,
        "rules": [{"domain_suffix": domain_list}]
    }
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def main():
    print("=== ЗАПУСК CHECKER.PY ===")
    
    # 1. Формирование Base64 подписки зарубежных прокси
    if os.path.exists("raw_combined.txt"):
        with open("raw_combined.txt", "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
        if lines:
            raw_text = "\n".join(sorted(list(set(lines))))
            b64_output = base64.b64encode(raw_text.encode('utf-8')).decode('utf-8')
            with open("proxy.txt", "w", encoding="utf-8") as f:
                f.write(b64_output)
            print("Успешно сформирован proxy.txt (Base64).")

    # 2. Формирование Base64 подписки RU прокси
    if os.path.exists("ru_nodes.txt"):
        with open("ru_nodes.txt", "r", encoding="utf-8") as f:
            ru_lines = [l.strip() for l in f if l.strip()]
        if ru_lines:
            ru_raw_text = "\n".join(ru_lines)
            ru_b64 = base64.b64encode(ru_raw_text.encode('utf-8')).decode('utf-8')
            with open("ru_proxies.txt", "w", encoding="utf-8") as rf:
                rf.write(ru_b64)
            print("Успешно сформирован ru_proxies.txt (Base64).")

    # 3. Скачивание и проверка доменов на доступность
    domains_to_test = load_domains_from_sources()
    print(f"Собрано {len(domains_to_test)} доменов для проверки availability...")

    blocked_list = []
    allowed_list = []

    # Многопоточный тест доменов
    if domains_to_test:
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(test_single_domain, dom): dom for dom in domains_to_test}
            for future in as_completed(futures):
                domain, is_blocked = future.result()
                if is_blocked:
                    blocked_list.append(domain)
                else:
                    allowed_list.append(domain)

    # Сохранение готовых списков
    save_rules_file("blocked.json", sorted(blocked_list))
    save_rules_file("allowed.json", sorted(allowed_list))
    print(f"Готово! Заблокировано: {len(blocked_list)}, Доступно: {len(allowed_list)}")

if __name__ == "__main__":
    main()