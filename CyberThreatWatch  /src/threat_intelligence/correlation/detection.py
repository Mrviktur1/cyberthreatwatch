# detections.py
from collections import deque
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network

# 1) IOC matcher
def ioc_match(event, iocs):
    hits = []
    ip = event.get("src_ip") or event.get("dst_ip")
    dom = event.get("domain")
    hsh = event.get("sha256") or event.get("md5")

    for i in iocs:
        t, v = i["type"], i["value"]
        if t == "ip":
            try:
                if ip_address(ip) in ip_network(v, strict=False):
                    hits.append(("ip", v))
            except:
                if ip == v:
                    hits.append(("ip", v))
        elif t == "domain" and dom and dom.endswith(v):
            hits.append(("domain", v))
        elif t == "hash" and hsh == v:
            hits.append(("hash", v))
    return hits


# 2) Brute-force login detection
def brute_force(events, window_min=5, threshold=8):
    window = deque()
    detections = []
    for e in events:
        if e["evt_type"] != "auth_failed":
            continue
        now = datetime.fromisoformat(e["ts"])
        window.append(e)
        # slide window
        while window and (now - datetime.fromisoformat(window[0]["ts"])) > timedelta(minutes=window_min):
            window.popleft()
        # count by user
        by_user = {}
        for w in window:
            by_user[w["user"]] = by_user.get(w["user"], 0) + 1
        for user, cnt in by_user.items():
            if cnt >= threshold:
                detections.append({
                    "title": "Possible brute force",
                    "user": user,
                    "count": cnt,
                    "severity": "high",
                    "rule_id": "BF-001"
                })
    return detections


# 3) Phishing domain heuristic (simple Levenshtein distance)
def looks_like_phishing(domain, brand="paypal.com"):
    import Levenshtein
    score = Levenshtein.distance(domain, brand)
    return score <= 2  # threshold
