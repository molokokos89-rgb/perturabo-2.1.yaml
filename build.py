#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Сборка правил для Karing (perturabo).
Основа — оригинальный build.py, только дополнения и починка мёртвых ссылок.
Ничего не удалено из рабочей логики.
"""

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
import yaml

RUS_JSON = "My_rules_RUS.json"
REJECT_JSON = "reject_rules.json"
PROXY_JSON = "my_rules_proxy.json"

PROXY_MANUAL_TXT = "proxy_manual.txt"
DIRECT_MANUAL_TXT = "direct_manual.txt"
REJECT_MANUAL_TXT = "reject_manual.txt"

DROPBOX_URL = "https://www.dropbox.com/scl/fi/759t1a2us3y0kblgat0xr/log-for-reject.txt?rlkey=zr2uqv81lx89rdl6q55geyucy&st=8lc13ygu&dl=1"

# ---------------------------------------------------------------------------
# SOURCES — старые оставлены (даже если часть 404), добавлены рабочие 2026
# ---------------------------------------------------------------------------
SOURCES = [
    # --- старые (могут быть 404, не мешают) ---
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS%2BAll_RUS.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/hy2.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    "https://raw.githubusercontent.com/freefq/free/master/v2ray",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
    # --- рабочие замены / дополнения ---
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ss.txt",
    "https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/config.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/all_extracted_configs.txt",
    "https://raw.githubusercontent.com/3inker/v2ray-subscription/main/all_not_ru.txt",
]

RULE_SOURCES = {
    "telegram": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/telegramcidr.txt",
    "google": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/google.txt",
    # apple/youtube/tiktok на raw иногда 404 — дубли через jsDelivr + proxy.txt
    "apple": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/apple.txt",
    "youtube": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/youtube.txt",
    "tiktok": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/tiktok.txt",
    "proxy_media": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt",
    "reject": "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt",
    "adguard_dns": "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/DNSFilter/sections/adservers.txt",
    "adguard_trackers": "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/DNSFilter/sections/spyware.txt",
    "oisd_small": "https://small.oisd.nl/domainswild",
    "stevenblack": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
}

HEAVY_SOURCES = [
    "https://raw.githubusercontent.com/roskomkod/ru-blocked-domains/main/domains.txt",
]

PROTOCOLS = ["ss://", "vmess://", "trojan://", "hy2://", "hysteria2://", "vless://"]
BAD_KEYWORDS = ["russia", "anycast", "offnet", "offcord", "cloudflare", "warp", "cf-"]

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

# Старые ключевые слова (оставлены)
AD_TRACKER_KEYWORDS = [
    "analytics", "ads", "pixel", "metrics", "telemetry", "tracker",
    "tracking", "adservice", "adsystem", "banner", "counter", "pangle",
    "bdtone", "doubleclick", "app-measurement", "adjust", "appsflyer"
]

# ДОПОЛНЕНИЕ: расширенные ad-паттерны (поддомены / куски имени)
AD_TRACKER_KEYWORDS_EXTRA = [
    "adserver", "adserving", "advert", "advertising", "adnxs", "admob",
    "adsense", "adform", "adition", "adtech", "advertising", "adsrvr",
    "scorecardresearch", "quantserve", "chartbeat", "hotjar", "mixpanel",
    "segment.io", "segment.com", "amplitude", "branch.io", "kochava",
    "singular", "tenjin", "ironsource", "applovin", "unityads", "vungle",
    "adcolony", "chartboost", "tapjoy", "supersonic", "fyber", "inmobi",
    "mopub", "pubmatic", "openx", "rubiconproject", "criteo", "taboola",
    "outbrain", "mgid", "revcontent", "exoclick", "popads", "propellerads",
    "adcash", "clicksor", "clickadu", "hilltopads", "trafficjunky",
    "juicyads", "exoclick", "adsterra", "richads", "adspyglass",
    "googlesyndication", "googleadservices", "pagead", "partner.googleadservices",
    "securepubads", "fundingchoices", "doubleclick", "2mdn", "googletagservices",
    "facebook.com/tr", "connect.facebook.net", "an.facebook.com",
    "ads.tiktok", "ads-api.tiktok", "business-api.tiktok", "pangle",
    "snssdk", "byteoversea.com/ad", "isnssdk", "ug-ad",
    "yandex.ru/ads", "an.yandex.ru", "mc.yandex.ru", "ads.vk.com",
    "top.mail.ru", "counter.yadro.ru", "liveinternet.ru", "rambler.ru/top100",
    "smi2", "relap", "sberads", "mytarget", "adfox", "adriver",
    "begun.ru", "marketgid", "tns-counter", "weborama", "mediametrics",
]

# ДОПОЛНЕНИЕ: чистые рекламные/трекерные домены (никогда не контент)
PURE_AD_DOMAINS = [
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "google-analytics.com", "googletagmanager.com", "googletagservices.com",
    "2mdn.net", "pagead2.googlesyndication.com", "adservice.google.com",
    "appsflyer.com", "adjust.com", "branch.io", "kochava.com",
    "pangle.io", "pangleglobal.com", "applovin.com", "unityads.unity3d.com",
    "ironsource.com", "supersonicads.com", "vungle.com", "adcolony.com",
    "chartboost.com", "tapjoy.com", "inmobi.com", "mopub.com",
    "pubmatic.com", "openx.net", "rubiconproject.com", "criteo.com",
    "taboola.com", "outbrain.com", "mgid.com", "exoclick.com",
    "propellerads.com", "adsterra.com", "juicyads.com", "trafficjunky.com",
    "scorecardresearch.com", "quantserve.com", "chartbeat.com",
    "hotjar.com", "mixpanel.com", "amplitude.com", "segment.com",
    "segment.io", "fullstory.com", "mouseflow.com", "crazyegg.com",
    "newrelic.com", "nr-data.net", "sentry.io", "bugsnag.com",
    "app-measurement.com", "crashlytics.com", "fabric.io",
    "facebook.net", "connect.facebook.net", "an.facebook.com",
    "tr.facebook.com", "pixel.facebook.com",
    "ads.tiktok.com", "ads-api.tiktok.com", "business-api.tiktok.com",
    "ads.yahoo.com", "advertising.yahoo.com", "adtech.yahooinc.com",
    "amazon-adsystem.com", "aax.amazon-adsystem.com",
    "moatads.com", "adsafeprotected.com", "integral-ads.com",
    "adform.net", "adnxs.com", "adsrvr.org", "bidswitch.net",
    "casalemedia.com", "contextweb.com", "smartadserver.com",
    "spotxchange.com", "teads.tv", "yieldmo.com", "sharethrough.com",
    "mytarget.ru", "adfox.ru", "adriver.ru", "begun.ru",
    "tns-counter.ru", "top.mail.ru", "counter.yadro.ru",
    "an.yandex.ru", "mc.yandex.ru", "ads.vk.com", "ads.sberbank.ru",
]

# ДОПОЛНЕНИЕ: контентные корни — НИКОГДА не в REJECT
CONTENT_WHITELIST = [
    # TikTok / ByteDance
    "tiktok.com", "tiktokv.com", "tiktokcdn.com", "musical.ly", "muscdn.com",
    "byteoversea.com", "ibytedtos.com", "bytegecko.com", "bytedance.com",
    "snssdk.com", "amemv.com", "toutiao.com", "pstatp.com",
    # Facebook / Meta / Instagram
    "facebook.com", "facebook.net", "fbcdn.net", "fb.com", "meta.com",
    "instagram.com", "cdninstagram.com", "whatsapp.com", "whatsapp.net",
    "messenger.com", "oculus.com",
    # YouTube / Google content (не ad-поддомены)
    "youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "ggpht.com",
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "google.ru", "g.co", "withgoogle.com",
    # Rutube / VK / Yandex content
    "rutube.ru", "vk.com", "vk.ru", "vk.me", "vk.org", "vk-cdn.net",
    "userapi.com", "vkuseraudio.net", "ok.ru", "ok.me", "okcdn.ru",
    "yandex.ru", "yandex.net", "yandex.com", "ya.ru", "yastatic.net",
    "dzen.ru", "kinopoisk.ru", "mail.ru",
    # Telegram
    "t.me", "telegram.org", "telegram.me", "telegram.dog", "tdesktop.com",
    "telegra.ph", "tx.me", "cdn-telegram.org", "telegram-cdn.org",
    # Apple
    "apple.com", "icloud.com", "icloud-content.com", "mzstatic.com",
    "cdn-apple.com", "me.com",
    # Прочее контент/игры (не ломать)
    "roblox.com", "roblox.net", "rbxcdn.com", "discord.com", "discordapp.com",
    "steam.com", "steampowered.com", "steamcommunity.com", "steamstatic.com",
    "twitch.tv", "ttvnw.net", "netflix.com", "nflxvideo.net",
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

    # --- УДАЛЯЕМ ВСЕ ПРЕФИКСЫ GFWList ---
    line = re.sub(r'^(\|\||@@\|\||\+\.|\+|\|\||@@)', '', line)
    line = re.sub(r'^\+[0-9]+@', '', line)
    line = re.sub(r'^\+@', '', line)
    line = re.sub(r'^(127\.0\.0\.1|0\.0\.0\.0|::1)\s+', '', line)

    if "#" in line:
        line = line.split("#")[0]
    line = line.strip().replace("^", "").strip(".-")
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
    if re.search(r'(^|\.)(ru|su|by|xn--p1ai)(\.|$)', domain_lower):
        return True
    return False


def is_content_whitelisted(domain):
    """Контентные корни (TikTok/FB/YouTube/Rutube/VK/Yandex и т.д.) — никогда в REJECT."""
    d = domain.lower().strip(".")
    for root in CONTENT_WHITELIST:
        root = root.lower().strip(".")
        if d == root or d.endswith("." + root):
            return True
    return False


def is_pure_ad_domain(domain):
    """Точное/суффиксное совпадение с известными чисто-рекламными доменами."""
    d = domain.lower().strip(".")
    for ad in PURE_AD_DOMAINS:
        ad = ad.lower().strip(".")
        if d == ad or d.endswith("." + ad):
            return True
    return False


def is_ad_or_tracker(domain):
    """
    Умная проверка:
    1) whitelist контента → False (не reject)
    2) pure ad domain → True
    3) ключевые слова (старые + новые) → True только если НЕ whitelist
    """
    if is_telegram_domain(domain):
        return False
    if is_content_whitelisted(domain):
        return False
    if is_pure_ad_domain(domain):
        return True
    d = domain.lower()
    all_keywords = AD_TRACKER_KEYWORDS + AD_TRACKER_KEYWORDS_EXTRA
    return any(keyword in d for keyword in all_keywords)


def load_links_from_txt(filename):
    urls = []
    if os.path.exists(filename):
        with open(filename, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith(("#", "//")):
                    urls.append(line)
    return urls


def _extract_from_json(data, domains_set, cidrs_set=None):
    if isinstance(data, list):
        for item in data:
            _extract_from_json(item, domains_set, cidrs_set)
    elif isinstance(data, dict):
        for key in ["domain_suffix", "domain", "domains", "host", "hosts"]:
            if key in data:
                items = data[key]
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, str):
                            if "/" in item and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+$', item):
                                if cidrs_set is not None:
                                    cidrs_set.add(item)
                            else:
                                d = clean_domain(item)
                                if d:
                                    domains_set.add(d)
                elif isinstance(items, str):
                    d = clean_domain(items)
                    if d:
                        domains_set.add(d)

        for key in ["ip_cidr", "cidr", "ip"]:
            if key in data:
                items = data[key]
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, str):
                            if cidrs_set is not None:
                                cidrs_set.add(item)
                elif isinstance(items, str):
                    if cidrs_set is not None:
                        cidrs_set.add(items)

        for key, value in data.items():
            if key not in ["domain_suffix", "domain", "domains", "host", "hosts", "ip_cidr", "cidr", "ip"]:
                if isinstance(value, (dict, list)):
                    _extract_from_json(value, domains_set, cidrs_set)


def process_url_content(url, domains_set, cidrs_set=None):
    content = fetch_url(url)
    if not content:
        return
    if content.strip().startswith(("{", "[")):
        try:
            data = json.loads(content)
            _extract_from_json(data, domains_set, cidrs_set)
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
    existing_data = {}
    if os.path.exists(filename):
        try:
            with open(filename, "r", encoding="utf-8") as f:
                existing_data = json.load(f)
        except Exception:
            pass

    existing_domains = set()
    existing_cidrs = set()
    existing_keywords = set()
    existing_regex = set()

    if "rules" in existing_data and existing_data["rules"]:
        for rule in existing_data["rules"]:
            existing_domains.update(rule.get("domain_suffix", []))
            existing_domains.update(rule.get("domain", []))
            existing_cidrs.update(rule.get("ip_cidr", []))
            existing_keywords.update(rule.get("domain_keyword", []))
            existing_regex.update(rule.get("domain_regex", []))

    combined_domains = existing_domains | set(domains)
    combined_cidrs = existing_cidrs | set(cidrs)

    rule_item = {}
    if combined_domains:
        rule_item["domain_suffix"] = sorted(list(combined_domains))
    if combined_cidrs:
        rule_item["ip_cidr"] = sorted(list(combined_cidrs))
    if existing_keywords:
        rule_item["domain_keyword"] = sorted(list(existing_keywords))
    if existing_regex:
        rule_item["domain_regex"] = sorted(list(existing_regex))

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
            params = urllib.parse.parse_qs(url.query)
            outbound = {
                "type": "hysteria2",
                "server": host,
                "server_port": port,
                "password": password,
                "tls": {"enabled": True}
            }
            if "sni" in params:
                outbound["tls"]["server_name"] = params["sni"][0]
            if "insecure" in params and params["insecure"][0] == "1":
                outbound["tls"]["insecure"] = True
            return outbound
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
            _extract_from_json(data, domains_set, cidrs_set)
            return
        except Exception:
            pass

    try:
        data = yaml.safe_load(content)
        if isinstance(data, (dict, list)):
            _extract_from_json(data, domains_set, cidrs_set)
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
        else:
            print(f"  [skip/404] {source}")
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
            f.write("\n".join(sorted(list(set(foreign_nodes)))))
    if ru_nodes:
        with open("ru_proxies.txt", "w", encoding="utf-8") as rf:
            rf.write("\n".join(sorted(list(set(ru_nodes)))))
    print(f"Готово! Записано: proxy.txt ({len(foreign_nodes)} нод), ru_proxies.txt ({len(ru_nodes)} нод)")


def step_parse_rules_and_sorting():
    print("\n--- 2. ЗАГРУЗКА И СОРТИРОВКА ПРАВИЛ ИЗ TXT-ФАЙЛОВ ---")
    reject_domains = set()
    reject_cidrs = set()
    direct_domains = set()
    direct_cidrs = set()
    proxy_domains = set()
    proxy_cidrs = set()

    manual_direct_domains = [
        "yabs.yandex.ru", "yastatic.net", "api.browser.yandex.ru",
        "init.itunes.apple.com", "bag.itunes.apple.com", "polaris-iot.com",
        "tk-kit.net", "boosty.to", "max.ru", "max.dev", "bitrix24.ru",
        "b24.ru", "bitrix24.com", "bitrix24.net", "bitrixlabs.ru",
        "bx24.net", "bx24.ru", "gosuslugi.ru", "mos.ru", "pgu.mos.ru",
        "rt.ru", "bio.rt.ru", "edu.ru", "sber.ru", "sberbank.ru",
        "tbank.ru", "tinkoff.ru", "vtb.ru", "cbr.ru", "alfabank.ru",
        "gazprombank.ru", "rshb.ru", "raiffeisen.ru", "nalog.ru",
        "nalog.gov.ru", "pfr.gov.ru", "sfr.gov.ru", "wb.ru",
        "wildberries.ru", "wbstatic.net", "wbbasket.ru", "ozon.ru",
        "ozon.com", "avito.ru", "ya.ru", "yandex.ru", "yandex.net",
        "yandex.com", "yandex.org", "dzen.ru", "vk.com", "vk.ru",
        "vk.me", "vk.org", "vk-cdn.net", "userapi.com", "vkuseraudio.net",
        "vk.cc", "vk-portal.net", "vkuserconnect.com", "vkat.me",
        "vk.company", "oneme.ru", "okcdn.ru", "ok.ru", "ok.me",
        "mail.ru", "inappstory.ru", "mindbox.ru", "magnit.ru",
        "kazanexpress.ru", "mm.ru", "kaspersky-labs.com", "dadata.ru",
        "flocktory.com", "selectel.ru", "selectel.com", "beget.com",
        "timeweb.ru", "reg.ru", "nic.ru", "rostelecom.ru", "megafon.ru",
        "mts.ru", "beeline.ru", "tele2.ru", "rutube.ru", "2gis.ru",
        "dgis.ru", "rzhd.ru", "rjd.ru", "aeroflot.ru", "s7.ru",
        "yoomoney.ru", "kinopoisk.ru", "afisha.ru", "odnoklassniki.ru",
        "lamoda.ru", "megamarket.ru", "api.okcdn.ru", "api.vk.ru",
        "eh.vk.com", "internal.api.vk.ru", "queuev4.vk.ru",
        "sun1-23.vkuserphoto.ru", "api.remanga.org", "dbankcloud.com",
        "dbankcdn.com", "huawei.com", "amazonaws.com", "ably.io",
        "pusher.com", "pubnub.com", "unity3d.com", "globalsign.com",
        "globalsign.dev", "digicert.com", "comodo.com", "letsencrypt.org",
        "sectigo.com"
    ]
    for d in manual_direct_domains:
        direct_domains.add(d)

    manual_proxy_domains = [
        "gstatic.gemini.com", "gemini.google.com", "aistudio.google.com",
        "generativelanguage.googleapis.com", "alkalimining-pa.googleapis.com",
        "proactivebackend-pa.googleapis.com", "google.ru", "google.com",
        "googleapis.com", "googleusercontent.com", "gstatic.com",
        "ggpht.com", "p76prod.systems", "bethesda.net", "zenimax.com",
        "fallout76.com", "amazongames.com", "g.co", "googleanalytics.com",
        "googletagmanager.com", "googlesyndication.com", "google-analytics.com",
        "googleadservices.com", "gvt1.com", "gvt2.com", "goo.gl",
        "youtube.com", "ytimg.com", "googlelabs.com", "github.com",
        "githubusercontent.com", "telegram.org", "telegram.me",
        "telegram.dog", "telegram.space", "tdesktop.org", "tdesktop.com",
        "telegra.ph", "telega.one", "t.me", "tx.me", "cdn-telegram.org",
        "telegram-cdn.org", "comments.app", "contest.com", "fragment.com",
        "graph.org", "quiz.directory", "telesco.pe", "tg.dev", "ton.org",
        "toncenter.com", "usercontent.dev", "apple.com", "icloud.com",
        "icloud-content.com", "me.com", "mzstatic.com", "apple-cloudkit.com",
        "apple-livephotoskit.com", "cdn-apple.com", "ampaeservices.com",
        "netflix.com", "facebook.com", "meta.com"
    ]
    for d in manual_proxy_domains:
        proxy_domains.add(d)

    for tg_dom in TELEGRAM_DOMAINS:
        proxy_domains.add(tg_dom)
    for tg_cidr in TELEGRAM_CIDRS:
        proxy_cidrs.add(tg_cidr)
    for wb_cidr in WILDBERRIES_CIDRS:
        proxy_cidrs.add(wb_cidr)

    # ДОПОЛНЕНИЕ: сразу кладём pure-ad в reject
    for ad in PURE_AD_DOMAINS:
        reject_domains.add(ad)

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

    # ДОПОЛНЕНИЕ: RULE_SOURCES (если не прописаны в manual-txt)
    for name, url in RULE_SOURCES.items():
        if name in ("reject", "adguard_dns", "adguard_trackers", "oisd_small", "stevenblack"):
            print(f"  RULE reject-source [{name}]: {url}")
            process_rule_source(url, reject_domains, reject_cidrs)
        elif name in ("telegram", "google", "youtube", "tiktok", "proxy_media"):
            print(f"  RULE proxy-source [{name}]: {url}")
            process_rule_source(url, proxy_domains, proxy_cidrs)
        elif name == "apple":
            print(f"  RULE direct/proxy-source [{name}]: {url}")
            process_rule_source(url, direct_domains, direct_cidrs)

    dropbox_content = fetch_url(DROPBOX_URL)
    if dropbox_content:
        print("  Обработка Dropbox-логов (только для REJECT, с whitelist):")
        for line in dropbox_content.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "!", ";", "//")):
                continue

            parts = line.split(',')
            if len(parts) < 6:
                continue

            domain = parts[4].strip()
            if not domain or domain.startswith('.'):
                continue

            if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$', domain, re.IGNORECASE):
                continue

            d = clean_domain(domain)
            if not d:
                continue

            if d in direct_domains or d in proxy_domains:
                print(f"    {d} -> ПРОПУЩЕН (уже в Direct/Proxy)")
                continue

            # ДОПОЛНЕНИЕ: whitelist контента — никогда в reject
            if is_content_whitelisted(d):
                if is_domestic_service(d):
                    direct_domains.add(d)
                    print(f"    {d} -> в DIRECT (whitelist + РФ)")
                else:
                    proxy_domains.add(d)
                    print(f"    {d} -> в PROXY (whitelist контент)")
                continue

            if is_domestic_service(d):
                direct_domains.add(d)
                print(f"    {d} -> в DIRECT (Российский сервис)")
            elif is_telegram_domain(d):
                proxy_domains.add(d)
                print(f"    {d} -> в PROXY (Telegram)")
            elif is_ad_or_tracker(d):
                reject_domains.add(d)
                print(f"    {d} -> в REJECT (реклама/трекер)")
            else:
                print(f"    {d} -> ПРОПУЩЕН (не реклама, не РФ)")

    # Финальная очистка: whitelist вычищаем из reject
    before = len(reject_domains)
    reject_domains = {d for d in reject_domains if not is_content_whitelisted(d)}
    print(f"  Очистка reject от whitelist: убрано {before - len(reject_domains)} доменов")

    proxy_domains = {d for d in proxy_domains if d not in reject_domains}
    proxy_cidrs = {c for c in proxy_cidrs if c not in reject_cidrs}
    direct_domains = {d for d in direct_domains if d not in reject_domains}
    direct_cidrs = {c for c in direct_cidrs if c not in reject_cidrs}
    direct_domains = {d for d in direct_domains if d not in proxy_domains}
    direct_cidrs = {c for c in direct_cidrs if c not in proxy_cidrs}

    EXCLUDED_DOMAINS = [
        "roblox.com",
        "roblox.net",
        "rbxcdn.com",
        "discord.com",
        "steam.com",
        "steampowered.com"
    ]

    for domain in EXCLUDED_DOMAINS:
        if domain in reject_domains:
            reject_domains.remove(domain)
            print(f"  {domain} -> УДАЛЁН из REJECT (исключение)")

    save_mixed_rules_file(REJECT_JSON, reject_domains, reject_cidrs)
    save_mixed_rules_file(RUS_JSON, direct_domains, direct_cidrs)
    save_mixed_rules_file(PROXY_JSON, proxy_domains, proxy_cidrs)

    print(f"\nСортировка завершена:")
    print(f" -> Реджекты/Реклама: {len(reject_domains)} доменов, {len(reject_cidrs)} CIDR")
    print(f" -> Прямой доступ (Direct): {len(direct_domains)} доменов, {len(direct_cidrs)} CIDR")
    print(f" -> Прокси: {len(proxy_domains)} доменов, {len(proxy_cidrs)} CIDR")


def step_compile_srs():
    print("\n--- 3. КОМПИЛЯЦИЯ В БИНАРНИКИ SING-BOX (.SRS) ---")
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


def main():
    print("==================================================")
    print("=== СБОРКА ПРАВИЛ ДЛЯ KARING (улучшенный build) ===")
    print("==================================================")
    step_collect_proxies()
    step_parse_rules_and_sorting()
    step_compile_srs()
    print("\n==================================================")
    print("=== ГОТОВО! ===")
    print("==================================================")


if __name__ == "__main__":
    main()
