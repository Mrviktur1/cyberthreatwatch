"""
detections.py
Rule-based detection functions for CyberThreatWatch
MITRE ATT&CK aligned
"""

from collections import deque
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network
import math

# -------------------------------------------------------------------
# 1) IOC Match (classic rule)
# -------------------------------------------------------------------
def ioc_match(event, iocs):
    hits = []
    ip = event.get("src_ip") or event.get("dst_ip") or event.get("source_ip")
    dom = event.get("domain")
    hsh = event.get("sha256") or event.get("md5") or event.get("file_hash")

    for i in iocs:
        t, v = i["type"], i["value"]
        if t == "ip":
            try:
                if ip and ip_address(ip) in ip_network(v, strict=False):
                    hits.append(("ip", v))
            except:
                if ip == v:
                    hits.append(("ip", v))
        elif t == "domain" and dom and dom.endswith(v):
            hits.append(("domain", v))
        elif t == "hash" and hsh == v:
            hits.append(("hash", v))
    
    if hits:
        return {
            "title": "IOC Match Detected",
            "rule_id": "IOC-001",
            "technique": "T1059",   # Command-Line or Scripted execution
            "severity": "critical",
            "hits": hits,
            "event_id": event.get("id", "unknown"),
            "source_ip": ip,
            "timestamp": event.get("timestamp", datetime.now().isoformat())
        }
    return None


# -------------------------------------------------------------------
# 2) Brute Force Detection
# -------------------------------------------------------------------
def brute_force(events, window_min=5, threshold=8):
    window = deque()
    detections = []
    
    for e in events:
        if e.get("evt_type") != "auth_failed" and e.get("event_type") != "authentication_failure":
            continue
        
        # Handle different timestamp formats
        ts = e.get("ts") or e.get("timestamp")
        if not ts:
            continue
            
        try:
            now = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        except:
            now = datetime.now()
            
        window.append(e)
        
        # slide window
        while window:
            first_ts = window[0].get("ts") or window[0].get("timestamp")
            if not first_ts:
                window.popleft()
                continue
                
            try:
                first_time = datetime.fromisoformat(first_ts.replace('Z', '+00:00'))
                if (now - first_time) > timedelta(minutes=window_min):
                    window.popleft()
                else:
                    break
            except:
                window.popleft()
        
        # count by user or source_ip
        by_source = {}
        for w in window:
            source = w.get("user") or w.get("source_ip") or w.get("src_ip") or "unknown"
            by_source[source] = by_source.get(source, 0) + 1
        
        for source, cnt in by_source.items():
            if cnt >= threshold:
                detections.append({
                    "title": "Brute Force Attempt Detected",
                    "rule_id": "BF-001",
                    "technique": "T1110",   # Brute Force
                    "source": source,
                    "attempts": cnt,
                    "severity": "high",
                    "event_id": e.get("id", "unknown"),
                    "timestamp": ts
                })
    
    return detections


# -------------------------------------------------------------------
# 3) Phishing domain heuristic (simple Levenshtein distance)
# -------------------------------------------------------------------
def looks_like_phishing(domain, brands=None):
    if brands is None:
        brands = ["paypal", "google", "microsoft", "amazon", "apple", "facebook", "netflix"]
    
    domain_lower = domain.lower()
    
    # Check for suspicious patterns
    suspicious_patterns = [
        r"\.(xyz|top|club|loan|win|tk|ml|ga|cf)$",  # Suspicious TLDs
        r"\d+-\d+-\d+-\d+",  # IP-like domains
        r"security-?update|verify-?account|login-?secure|password-?reset"  # Common phishing terms
    ]
    
    import re
    for pattern in suspicious_patterns:
        if re.search(pattern, domain_lower):
            return True
    
    # Check for brand impersonation using Levenshtein distance
    try:
        import Levenshtein
        for brand in brands:
            brand_domain = f"{brand}.com"
            score = Levenshtein.distance(domain_lower, brand_domain)
            if score <= 2:  # threshold
                return True
    except ImportError:
        # Fallback: simple substring check if Levenshtein not available
        for brand in brands:
            if brand in domain_lower and domain_lower != f"{brand}.com":
                return True
    
    return False


# -------------------------------------------------------------------
# 4) Impossible Travel / Geo-Velocity
# -------------------------------------------------------------------
def haversine(loc1, loc2):
    """Great-circle distance (km) between two (lat,lon) tuples"""
    lat1, lon1 = loc1
    lat2, lon2 = loc2
    R = 6371  # Earth radius in km
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlambda/2)**2
    return 2*R*math.atan2(math.sqrt(a), math.sqrt(1 - a))

def impossible_travel(logins, geoip_lookup, max_speed_kmph=1000):
    detections = []
    logins_sorted = sorted(logins, key=lambda x: x.get("ts") or x.get("timestamp"))
    
    for i in range(len(logins_sorted)-1):
        user = logins_sorted[i].get("user") or logins_sorted[i].get("source_ip")
        ip1, ip2 = logins_sorted[i].get("ip"), logins_sorted[i+1].get("ip")
        
        if not ip1 or not ip2:
            continue
            
        t1_str = logins_sorted[i].get("ts") or logins_sorted[i].get("timestamp")
        t2_str = logins_sorted[i+1].get("ts") or logins_sorted[i+1].get("timestamp")
        
        if not t1_str or not t2_str:
            continue
            
        try:
            t1 = datetime.fromisoformat(t1_str.replace('Z', '+00:00'))
            t2 = datetime.fromisoformat(t2_str.replace('Z', '+00:00'))
        except:
            continue
            
        loc1, loc2 = geoip_lookup(ip1), geoip_lookup(ip2)  # should return (lat, lon)
        
        if not loc1 or not loc2:
            continue
            
        distance = haversine(loc1, loc2)
        hours = (t2 - t1).total_seconds() / 3600
        
        if hours > 0 and (distance / hours) > max_speed_kmph:
            detections.append({
                "title": "Impossible Travel Login Detected",
                "rule_id": "GEO-001",
                "technique": "T1078",  # Valid Accounts
                "user": user,
                "from_ip": ip1,
                "to_ip": ip2,
                "from_location": loc1,
                "to_location": loc2,
                "distance_km": round(distance, 2),
                "speed_kmph": round(distance / hours, 2),
                "severity": "high",
                "timestamp": t2_str
            })
    
    return detections


# -------------------------------------------------------------------
# 5) DNS Tunneling Detection
# -------------------------------------------------------------------
def shannon_entropy(s):
    """Calculate Shannon entropy of a string"""
    if not s:
        return 0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum([p * math.log(p, 2) for p in prob if p > 0])

def dns_tunnel_detection(event, entropy_threshold=4.0, length_threshold=50):
    qname = event.get("domain") or event.get("query")
    
    if qname and (len(qname) > length_threshold or shannon_entropy(qname) > entropy_threshold):
        return {
            "title": "Possible DNS Tunneling Detected",
            "rule_id": "DNS-001",
            "technique": "T1071",  # Application Layer Protocol
            "domain": qname,
            "entropy": round(shannon_entropy(qname), 2),
            "length": len(qname),
            "severity": "critical",
            "event_id": event.get("id", "unknown"),
            "timestamp": event.get("timestamp", datetime.now().isoformat())
        }
    return None


# -------------------------------------------------------------------
# 6) Honeytoken File Access
# -------------------------------------------------------------------
def honeytoken_access(event):
    fname = event.get("file_name", "").lower()
    honeytoken_keywords = ["honeytoken", "password", "secret", "credential", "key", "token"]
    
    for keyword in honeytoken_keywords:
        if keyword in fname:
            return {
                "title": "Honeytoken File Access Detected",
                "rule_id": "HON-001",
                "technique": "T1530",  # Data from Cloud Storage Object
                "file": event.get("file_name"),
                "severity": "critical",
                "event_id": event.get("id", "unknown"),
                "source_ip": event.get("source_ip") or event.get("src_ip"),
                "timestamp": event.get("timestamp", datetime.now().isoformat())
            }
    return None


# -------------------------------------------------------------------
# 7) Run All Detections
# -------------------------------------------------------------------
def run_all_detections(events, iocs, geoip_lookup=None):
    """Run all detection rules on events"""
    all_detections = []
    
    for event in events:
        # IOC Matching
        ioc_result = ioc_match(event, iocs)
        if ioc_result:
            all_detections.append(ioc_result)
        
        # DNS Tunneling
        dns_result = dns_tunnel_detection(event)
        if dns_result:
            all_detections.append(dns_result)
        
        # Honeytoken Access
        honeytoken_result = honeytoken_access(event)
        if honeytoken_result:
            all_detections.append(honeytoken_result)
    
    # Brute Force (needs multiple events)
    brute_force_results = brute_force(events)
    all_detections.extend(brute_force_results)
    
    # Impossible Travel (needs multiple events and geoip)
    if geoip_lookup:
        login_events = [e for e in events if e.get("event_type") in ["login", "authentication"]]
        travel_results = impossible_travel(login_events, geoip_lookup)
        all_detections.extend(travel_results)
    
    # Phishing domains (single event)
    for event in events:
        domain = event.get("domain")
        if domain and looks_like_phishing(domain):
            all_detections.append({
                "title": "Suspicious Phishing Domain Detected",
                "rule_id": "PHISH-001",
                "technique": "T1566",  # Phishing
                "domain": domain,
                "severity": "medium",
                "event_id": event.get("id", "unknown"),
                "source_ip": event.get("source_ip") or event.get("src_ip"),
                "timestamp": event.get("timestamp", datetime.now().isoformat())
            })
    
    return all_detections