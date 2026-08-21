import urllib.request
import base64
import re
import socket
import json

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

def extract_ip_or_domain(proxy_link):
    try:
        if proxy_link.startswith("vmess://"):
            b64_str = proxy_link.split("://")[1]
            decoded = json.loads(safe_b64decode(b64_str))
            return decoded.get("add", "").strip()
        clean_link = re.sub(r'^[a-zA-Z0-9\-\.]+://', '', proxy_link)
        server_part = clean_link.split('@')[-1] if '@' in clean_link else clean_link
        return re.split(r'[:/?#]', server_part)[0].strip()
    except Exception:
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

def check_is_russia(node_line, host):
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
        req = urllib.request.Request(f"http://ip-api.com{ip}?fields=countryCode", headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
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
                    missing_padding = len(clean_content) % 4
                    if missing_padding:
                        clean_content += '=' * (4 - missing_padding)
                    content = base64.b64decode(clean_content).decode('utf-8', errors='ignore')
                except Exception:
                    pass
            return content
    except Exception:
        return ""

def main():
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
    foreign_nodes = []
    ru_nodes = []

    for node in unique_nodes:
        if not is_valid_reality(node):
            continue
        host = extract_ip_or_domain(node)
        if check_is_russia(node, host):
            ru_nodes.append(node)
        else:
            foreign_nodes.append(node)

    with open("raw_combined.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(foreign_nodes) + "\n")
    with open("ru_nodes.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(ru_nodes) + "\n")

if __name__ == "__main__":
    main()
