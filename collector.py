import urllib.request
import base64
import re
import socket
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS%2Ball_RUS.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscript10n/main/protocols/hy2.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    "https://raw.githubusercontent.com/freefq/free/master/v2ray",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt"
]

PROTOCOLS = ["ss://", "vmess://", "trojan://", "hy2://", "hysteria2://", "vless://"]
BAD_KEYWORDS = ["anycast", "fixnet", "fixcord", "cloudflare", "warp", "cf-"]
RU_MARKERS = ["russia", "moscow", "spb", "россия", ".ru"]

def safe_b64decode(data):
    data = data.strip()
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.b64decode(data).decode('utf-8', errors='ignore')

def extract_host_and_port(proxy_link):
    """Извлекает Host и Port из любой прокси-ссылки"""
    try:
        if proxy_link.startswith("vmess://"):
            b64_str = proxy_link.split("://")[1]
            decoded = json.loads(safe_b64decode(b64_str))
            return decoded.get("add", "").strip(), int(decoded.get("port", 443))
        
        clean_link = re.sub(r'^[a-zA-Z0-9\-\.]+://', '', proxy_link)
        server_part = clean_link.split('@')[-1] if '@' in clean_link else clean_link
        host_port = re.split(r'[/?#]', server_part)[0].strip()
        
        if ':' in host_port:
            host, port = host_port.rsplit(':', 1)
            return host.strip("[]"), int(port)
        return host_port.strip("[]"), 443
    except Exception:
        return None, None

def ping_tcp_node(proxy_link):
    """Быстро проверяет, открыт ли сетевой порт ноды"""
    host, port = extract_host_and_port(proxy_link)
    if not host or not port:
        return proxy_link, False, host
    
    try:
        with socket.create_connection((host, port), timeout=2.5):
            return proxy_link, True, host
    except Exception:
        return proxy_link, False, host

def check_is_russia(node_line, host):
    """Проверка страны IP (исправлен слэш в URL)"""
    if not host:
        return False
    if any(marker in node_line.lower() for marker in RU_MARKERS) or host.lower().endswith('.ru'):
        return True
    try:
        try:
            socket.inet_aton(host)
            ip = host
        except socket.error:
            ip = socket.gethostbyname(host)
            
        req = urllib.request.Request(f"http://ip-api.com/json/{ip}?fields=countryCode", headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=2) as response:
            data = json.loads(response.read().decode('utf-8'))
            return data.get("countryCode") == "RU"
    except Exception:
        pass
    return False

def fetch_url(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8', errors='ignore')
            if not any(proto in content for proto in PROTOCOLS):
                try:
                    clean_content = content.strip().replace("\n", "").replace("\r", "")
                    content = safe_b64decode(clean_content)
                except Exception:
                    pass
            return content
    except Exception:
        return ""

def main():
    print("=== ЗАПУСК COLLECTOR.PY ===")
    raw_nodes = []
    for source in SOURCES:
        data = fetch_url(source)
        if data:
            for line in data.splitlines():
                line = line.strip()
                if any(line.startswith(proto) for proto in PROTOCOLS):
                    if not any(bad in line.lower() for bad in BAD_KEYWORDS):
                        raw_nodes.append(line)
                        
    unique_nodes = list(set(raw_nodes))
    print(f"Собрано {len(unique_nodes)} уникальных нод из источников. Проверка портов в 30 потоков...")

    # Проверка отклика порта у собранных нод
    alive_nodes = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(ping_tcp_node, node): node for node in unique_nodes}
        for future in as_completed(futures):
            node, is_alive, host = future.result()
            if is_alive:
                alive_nodes.append((node, host))

    print(f"Живых нод (прошли TCP ping): {len(alive_nodes)}")

    foreign_nodes = []
    ru_nodes = []

    for node, host in alive_nodes:
        if check_is_russia(node, host):
            ru_nodes.append(node)
        else:
            foreign_nodes.append(node)

    # Запись результатов в файлы
    with open("raw_combined.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(foreign_nodes) + "\n")
        
    with open("proxy.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(foreign_nodes) + "\n")
        
    with open("ru_nodes.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(ru_nodes) + "\n")

    print(f"Завершено! В proxy.txt сохранено {len(foreign_nodes)} зарубежных рабочих серверов.")

if __name__ == "__main__":
    main()