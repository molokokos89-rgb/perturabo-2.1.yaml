#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Сборка правил для Karing (perturabo).
Сборка правил + прокси для Karing (perturabo 2.1).
Прокси: hy2 > trojan > ss, без vless, дедуп host:port, лимиты, parallel geo.
Правила: whitelist TikTok/FB/Rutube/YT/VK/Yandex, pure-ad reject, Dropbox-логи.
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
    # EbraSha hy2 (рабочие пути 2026)
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/separated-protocols/hysteria2_configs.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/separated-protocols-chunks/hysteria2/EbraSha-Protocol-Chunks-hysteria2-001.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/separated-protocols/trojan_configs.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/trojan_configs.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/ss_configs.txt",
    # barry-far
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ss.txt",
    # прочее (без гигантских all-in-one дампов)
    "https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/config.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS%2BAll_RUS.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/hy2.txt",
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

PROTOCOLS = ["hy2://", "hysteria2://", "trojan://", "ss://", "vmess://"]  # без vless (ТПУ)
PROTOCOL_PRIORITY = {"hy2://": 0, "hysteria2://": 0, "trojan://": 1, "ss://": 2, "vmess://": 3}
MAX_PER_SOURCE = 150
MAX_FOREIGN_TOTAL = 700
GEO_WORKERS = 32
_geo_cache = {}
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
        content = content.replace('&amp;', '&')
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


def extract_host_port(proxy_link):
    """(host, port) для дедупа."""
    try:
        line = proxy_link.strip()
        if "%" in line:
            try:
                line = urllib.parse.unquote(line)
            except Exception:
                pass
        if line.startswith("ss://"):
            part = line.split("://")[1].split("#")[0]
            if "@" in part:
                hp = part.split("@")[1]
            else:
                hp = safe_b64decode(part).split("@")[1]
            host = hp.split(":")[0].strip("[]")
            port = hp.split(":")[1].split("/")[0].split("?")[0]
            return host, port
        if line.startswith(("trojan://", "hy2://", "hysteria2://", "vless://")):
            rest = line.split("://")[1]
            hp = rest.split("@")[1] if "@" in rest else rest
            host = hp.split(":")[0].split("?")[0].strip("[]")
            port = hp.split(":")[1].split("/")[0].split("?")[0].split("#")[0]
            return host, port
        if line.startswith("vmess://"):
            data = json.loads(safe_b64decode(line.split("://")[1].split("?")[0]))
            return str(data.get("add", "")).strip("[]"), str(data.get("port", ""))
    except Exception:
        return None, None
    return None, None


def protocol_of(link):
    low = link.lower()
    for p in PROTOCOLS:
        if low.startswith(p):
            return p
    return "unknown://"


def _check_is_russia_uncached(host):
    if not host:
        return False
    if host.lower().endswith((".ru", ".su", ".by", ".рф")):
        return True
    try:
        try:
            socket.inet_aton(host)
            ip = host
        except OSError:
            ip = socket.gethostbyname(host)
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip}?fields=status,countryCode",
            headers={"User-Agent": "Mozilla/5.0"},
        )
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode("utf-8"))
            if data.get("status") == "success" and data.get("countryCode") == "RU":
                return True
    except Exception:
        pass
    return False


def check_is_russia(host):
    if host in _geo_cache:
        return _geo_cache[host]
    result = _check_is_russia_uncached(host)
    _geo_cache[host] = result
    return result


def batch_geo_check(hosts):
    unique = [h for h in set(hosts) if h and h not in _geo_cache]
    if not unique:
        return
    print(f"  geo-check: {len(unique)} hosts, workers={GEO_WORKERS}")
    with ThreadPoolExecutor(max_workers=GEO_WORKERS) as ex:
        futs = {ex.submit(_check_is_russia_uncached, h): h for h in unique}
        done = 0
        for fut in as_completed(futs):
            h = futs[fut]
            try:
                _geo_cache[h] = fut.result()
            except Exception:
                _geo_cache[h] = False
            done += 1
            if done % 50 == 0 or done == len(unique):
                print(f"    geo progress: {done}/{len(unique)}")


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
    print("\n--- 1. СБОР И ФИЛЬТРАЦИЯ ПРОКСИ (hy2>trojan>ss, no vless, parallel geo) ---")
    from collections import defaultdict
    per_source = defaultdict(int)
    candidates = {}  # host:port -> link

    for source in SOURCES:
        print(f"  Source: {source}")
        data = fetch_url(source)
        if not data:
            print("    [skip/404]")
            continue
        seen = set()
        for line in data.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.lower().startswith("vless://"):
                continue
            if not any(line.startswith(p) for p in PROTOCOLS):
                continue
            if any(bad in line.lower() for bad in BAD_KEYWORDS):
                continue
            host, port = extract_host_port(line)
            if not host or not port:
                continue
            key = f"{host}:{port}"
            if key in seen:
                continue
            if per_source[source] >= MAX_PER_SOURCE:
                break
            seen.add(key)
            per_source[source] += 1
            prio = PROTOCOL_PRIORITY.get(protocol_of(line), 99)
            if key not in candidates or prio < PROTOCOL_PRIORITY.get(protocol_of(candidates[key]), 99):
                candidates[key] = line
        print(f"    taken: {per_source[source]}")

    hosts = []
    for key, link in candidates.items():
        h, _ = extract_host_port(link)
        if h:
            hosts.append(h)
    batch_geo_check(hosts)

    foreign_nodes, ru_nodes = [], []
    for key, link in candidates.items():
        h, _ = extract_host_port(link)
        if check_is_russia(h):
            ru_nodes.append(link)
        else:
            foreign_nodes.append(link)

    def sort_key(link):
        return (PROTOCOL_PRIORITY.get(protocol_of(link), 99), link)

    foreign_nodes = sorted(set(foreign_nodes), key=sort_key)[:MAX_FOREIGN_TOTAL]
    ru_nodes = sorted(set(ru_nodes), key=sort_key)

    if foreign_nodes:
        with open("proxy.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(foreign_nodes) + "\n")
    if ru_nodes:
        with open("ru_proxies.txt", "w", encoding="utf-8") as rf:
            rf.write("\n".join(ru_nodes) + "\n")

    hy2_n = sum(1 for x in foreign_nodes if protocol_of(x) in ("hy2://", "hysteria2://"))
    print(f"Готово! proxy.txt={len(foreign_nodes)} (hy2={hy2_n}), ru_proxies.txt={len(ru_nodes)}")


d