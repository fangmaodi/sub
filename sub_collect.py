#!/usr/bin/env python3
"""Collect nodes from go4sharing/sub, merge, dedupe, output Clash YAML."""
import sys
import urllib.request
import yaml

SOURCES = [
    "https://raw.githubusercontent.com/go4sharing/sub/main/sub.yaml",
    "https://raw.githubusercontent.com/go4sharing/sub/main/clash.yaml",
]


def fetch_yaml(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return yaml.safe_load(r.read().decode("utf-8", "ignore")) or {}


def main():
    seen = set()
    proxies = []
    for url in SOURCES:
        try:
            data = fetch_yaml(url)
        except Exception as e:
            print(f"fetch failed {url}: {e}")
            continue
        items = data.get("proxies") or []
        added = 0
        for p in items:
            if not isinstance(p, dict):
                continue
            if not p.get("server") or not p.get("port") or not p.get("type"):
                continue
            key = (p.get("type"), p.get("server"), p.get("port"))
            if key in seen:
                continue
            seen.add(key)
            p = dict(p)
            p.pop("delay", None)
            proxies.append(p)
            added += 1
        print(f"{url}: {len(items)} proxies, +{added} nodes")
    if not proxies:
        print("no proxies fetched, keeping old files")
        sys.exit(1)
    names = [p["name"] for p in proxies]
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
                "proxies": ["AUTO"] + names,
            },
            {
                "name": "AUTO",
                "type": "url-test",
                "proxies": names,
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
