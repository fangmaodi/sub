#!/usr/bin/env python3
"""Collect free public proxy nodes, merge, dedupe, output Clash YAML."""
import base64
import re
import sys
import urllib.request
import yaml

SOURCES = [
    "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.txt",
]

MAX_PROXIES = 500
PER_SOURCE_CAP = 500


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "ignore")


def decode_b64(s):
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s).decode("utf-8", "ignore")


def parse_links(text):
    links = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith(("vmess://", "vless://", "trojan://", "ss://", "ssr://")):
            links.append(line)
        else:
            try:
                decoded = decode_b64(line)
                for l in decoded.splitlines():
                    l = l.strip()
                    if l.startswith(("vmess://", "vless://", "trojan://", "ss://", "ssr://")):
                        links.append(l)
            except Exception:
                pass
    return links


def parse_vmess(link):
    try:
        d = yaml.safe_load(decode_b64(link[8:]))
        return {
            "name": d.get("ps", "vmess"),
            "type": "vmess",
            "server": d.get("add"),
            "port": int(d.get("port", 443)),
            "uuid": d.get("id"),
            "alterId": int(d.get("aid", 0)),
            "cipher": d.get("scy", "auto"),
            "tls": d.get("tls") == "tls",
            "network": d.get("net", "tcp"),
        }
    except Exception:
        return None


def parse_vless(link):
    m = re.match(r"vless://([^@]+)@([^:]+):(\d+)(?:\?([^#]*))?(?:#(.*))?", link)
    if not m:
        return None
    uuid, server, port, query, name = m.groups()
    params = dict(re.findall(r"([^=&]+)=([^&]*)", query or ""))
    return {
        "name": name or "vless",
        "type": "vless",
        "server": server,
        "port": int(port),
        "uuid": uuid,
        "tls": params.get("security") == "tls",
        "network": params.get("type", "tcp"),
        "servername": params.get("sni", ""),
    }


def parse_trojan(link):
    m = re.match(r"trojan://([^@]+)@([^:]+):(\d+)(?:\?([^#]*))?(?:#(.*))?", link)
    if not m:
        return None
    pwd, server, port, query, name = m.groups()
    params = dict(re.findall(r"([^=&]+)=([^&]*)", query or ""))
    return {
        "name": name or "trojan",
        "type": "trojan",
        "server": server,
        "port": int(port),
        "password": pwd,
        "sni": params.get("sni", server),
        "skip-cert-verify": True,
        "udp": True,
    }


def parse_ss(link):
    try:
        body = link[5:]
        if "#" in body:
            body, name = body.split("#", 1)
        else:
            name = "ss"
        if "@" not in body:
            body = decode_b64(body)
        if "@" in body:
            userinfo, hostport = body.rsplit("@", 1)
            if ":" not in userinfo:
                userinfo = decode_b64(userinfo)
            method, password = userinfo.split(":", 1)
            server, port = hostport.rsplit(":", 1)
            return {
                "name": name,
                "type": "ss",
                "server": server,
                "port": int(port),
                "cipher": method,
                "password": password,
                "udp": True,
            }
    except Exception:
        return None
    return None


def parse_node(link):
    if link.startswith("vmess://"):
        return parse_vmess(link)
    if link.startswith("vless://"):
        return parse_vless(link)
    if link.startswith("trojan://"):
        return parse_trojan(link)
    if link.startswith("ss://"):
        return parse_ss(link)
    return None


def main():
    seen = set()
    proxies = []
    for url in SOURCES:
        if len(proxies) >= MAX_PROXIES:
            break
        try:
            text = fetch(url)
            links = parse_links(text)
        except Exception as e:
            print(f"fetch failed {url}: {e}")
            continue
        added = 0
        for link in links:
            if added >= PER_SOURCE_CAP or len(proxies) >= MAX_PROXIES:
                break
            key = link.split("#")[0]
            if key in seen:
                continue
            seen.add(key)
            node = parse_node(link)
            if node and node.get("server") and node.get("port"):
                proxies.append(node)
                added += 1
        print(f"{url}: {len(links)} links, +{added} nodes")
    if not proxies:
        print("no proxies fetched, keeping old files")
        sys.exit(1)
    config = {
        "port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "external-controller": ":9090",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "PROXY",
                "type": "select",
                "proxies": ["AUTO"] + [p["name"] for p in proxies[:50]],
            },
            {
                "name": "AUTO",
                "type": "url-test",
                "proxies": [p["name"] for p in proxies[:50]],
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
            },
        ],
        "rules": ["MATCH,PROXY"],
    }
    with open("clash.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)
    with open("sub.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)
    print(f"total proxies: {len(proxies)}")


if __name__ == "__main__":
    main()
