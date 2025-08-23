import re
import math
import random
from collections import Counter
from supabase import create_client, Client
import os
from datetime import datetime


# --- Supabase Setup ---
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


# --- Severity helper ---
def _get_severity_for_rule(rule_name):
    severity_map = {
        "SQL Injection": "critical",
        "XSS Attack": "high",
        "Command Injection": "critical",
        "Path Traversal": "high",
        "Failed Login": "medium",
        "Multiple Failed Attempts": "high",
        "Suspicious IP": "low",
        "File Upload": "medium",
        "Information Disclosure": "medium",
        "Authentication Bypass": "high",
        "Data Exfiltration": "critical",
        "IOC Match - Malicious IP": "critical",
    }
    return severity_map.get(rule_name, "medium")


# --- Technique helper ---
def _get_technique_for_rule(rule_name):
    technique_map = {
        "SQL Injection": "T1190",
        "XSS Attack": "T1059",
        "Command Injection": "T1059",
        "Path Traversal": "T1190",
        "Failed Login": "T1110",
        "Multiple Failed Attempts": "T1110",
        "Suspicious IP": "T1071",
        "File Upload": "T1135",
        "Information Disclosure": "T1082",
        "Authentication Bypass": "T1078",
        "Data Exfiltration": "T1041",
        "IOC Match - Malicious IP": "T1589",
    }
    return technique_map.get(rule_name, "T1059")


# --- Store alerts in Supabase ---
def save_alert_to_supabase(rule, details, severity, technique, confidence):
    try:
        supabase.table("alerts").insert(
            {
                "rule": rule,
                "details": str(details),
                "severity": severity,
                "technique": technique,
                "confidence": confidence,
                "timestamp": datetime.utcnow().isoformat(),
            }
        ).execute()
    except Exception as e:
        print("⚠️ Failed to save alert:", e)


# --- Detection Functions ---
def run_detection(events):
    detections = []
    for event in events:
        if "sql" in event.get("query", "").lower():
            detections.append(
                {
                    "rule": "SQL Injection",
                    "details": event,
                    "severity": _get_severity_for_rule("SQL Injection"),
                }
            )
        if "<script>" in event.get("payload", "").lower():
            detections.append(
                {
                    "rule": "XSS Attack",
                    "details": event,
                    "severity": _get_severity_for_rule("XSS Attack"),
                }
            )
        if "failed login" in event.get("message", "").lower():
            detections.append(
                {
                    "rule": "Failed Login",
                    "details": event,
                    "severity": _get_severity_for_rule("Failed Login"),
                }
            )
    return detections


def run_anomaly_detection(events):
    anomalies = []
    ip_counter = Counter(event.get("ip") for event in events if event.get("ip"))
    for ip, count in ip_counter.items():
        if count > 50:
            anomalies.append(
                {
                    "rule": "Suspicious IP",
                    "details": {"ip": ip, "count": count},
                    "severity": "high",
                }
            )
    return anomalies


def run_correlation(events, iocs):
    correlations = []
    for event in events:
        if event.get("ip") in iocs.get("malicious_ips", []):
            correlations.append(
                {
                    "rule": "IOC Match - Malicious IP",
                    "details": event,
                    "severity": "critical",
                }
            )
    return correlations


def run_hybrid_detection(events, iocs):
    detections = run_detection(events)
    anomalies = run_anomaly_detection(events)
    correlations = run_correlation(events, iocs)

    hybrid_results = detections + anomalies + correlations

    for detection in hybrid_results:
        detection["confidence"] = random.choice(["low", "medium", "high"])
        detection["technique"] = _get_technique_for_rule(detection["rule"])

        # Save each detection into Supabase
        save_alert_to_supabase(
            detection["rule"],
            detection["details"],
            detection["severity"],
            detection["technique"],
            detection["confidence"],
        )

    return hybrid_results


def run_all_detections(events, iocs=None):
    results = {
        "detections": run_detection(events),
        "anomalies": run_anomaly_detection(events),
        "correlations": run_correlation(events, iocs or {}),
        "hybrid": run_hybrid_detection(events, iocs or {}),
    }
    return results
