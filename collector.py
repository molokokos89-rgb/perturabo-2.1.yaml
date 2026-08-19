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
                    decoded = base64.b64decode(clean_content).decode('utf-8', errors='ignore')
                    if any(proto in decoded for proto in PROTOCOLS):
                        content = decoded
                except Exception:
                    pass
            return content.splitlines()
    except Exception:
        return []

def main():
    all_proxies = []
    for url in SOURCES:
        lines = fetch_url(url)
        for line in lines:
            line = line.strip()
            if line and any(line.startswith(proto) for proto in PROTOCOLS):
                all_proxies.append(line)

    unique_proxies = sorted(list(set(all_proxies)))

    with open("raw_combined.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(unique_proxies))

if __name__ == "__main__":
    main()