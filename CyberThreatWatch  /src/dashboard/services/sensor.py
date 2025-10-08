# dashboard/services/sensor.py

import streamlit as st
import logging
import platform
import os
import time
import threading
from datetime import datetime
from supabase import create_client

logger = logging.getLogger(__name__)

# --- Initialize Supabase ---
@st.cache_resource
def get_supabase():
    try:
        url = st.secrets["SUPABASE_URL"]
        key = st.secrets["SUPABASE_KEY"]
        client = create_client(url, key)
        logger.info("✅ Connected to Supabase.")
        return client
    except Exception as e:
        logger.error(f"Supabase init failed: {e}")
        return None

supabase = get_supabase()


# --- Read Logs ---
def read_logs():
    """Reads latest 10 logs from OS."""
    system = platform.system().lower()
    logs = []

    try:
        if "windows" in system:
            os.system("wevtutil qe System /c:10 /f:text > system_logs.txt")
        elif "linux" in system or "darwin" in system:
            os.system("dmesg | tail -n 10 > system_logs.txt")

        if os.path.exists("system_logs.txt"):
            with open("system_logs.txt", "r", errors="ignore") as f:
                logs = [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"Log read error: {e}")

    return logs[-10:] if logs else []


# --- Send Logs to Supabase ---
def send_logs_to_supabase():
    """Uploads logs to Supabase alerts table."""
    logs = read_logs()
    if not logs:
        logger.warning("⚠️ No logs found to send.")
        return

    try:
        records = [
            {
                "source": platform.node(),
                "timestamp": datetime.utcnow().isoformat(),
                "message": log,
                "severity": classify_log(log),
                "type": detect_threat_type(log),
            }
            for log in logs
        ]

        supabase.table("alerts").insert(records).execute()
        logger.info(f"🧠 {len(records)} logs sent to Supabase.")
    except Exception as e:
        logger.error(f"Failed to send logs: {e}")


# --- Simple AI-ish threat classification ---
def classify_log(log: str):
    """Assign severity based on keywords."""
    log_lower = log.lower()
    if any(k in log_lower for k in ["error", "failed", "attack", "malware"]):
        return "high"
    elif any(k in log_lower for k in ["warning", "unauthorized", "retry"]):
        return "medium"
    return "info"


def detect_threat_type(log: str):
    """Detect type of alert based on keywords."""
    log_lower = log.lower()
    if "attack" in log_lower:
        return "Network Attack"
    elif "malware" in log_lower:
        return "Malware Detection"
    elif "unauthorized" in log_lower:
        return "Unauthorized Access"
    elif "failed" in log_lower:
        return "System Error"
    return "General Activity"


# --- Background Sensor ---
def start_sensor():
    """Continuously sends logs to Supabase every minute."""
    if st.session_state.get("sensor_running", False):
        st.info("⚙️ Sensor is already running.")
        return

    st.session_state["sensor_running"] = True

    def loop():
        while st.session_state.get("sensor_running", False):
            send_logs_to_supabase()
            time.sleep(60)  # every 1 minute

    threading.Thread(target=loop, daemon=True).start()
    st.success("🛰️ Sensor started — sending system logs to Supabase every minute.")


def stop_sensor():
    """Stop background log streaming."""
    st.session_state["sensor_running"] = False
    st.warning("🛑 Sensor stopped.")
