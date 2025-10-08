# dashboard/services/sensor.py
import streamlit as st
import logging
import platform
import os
import time
from datetime import datetime
from supabase import create_client

logger = logging.getLogger(__name__)

@st.cache_resource
def get_supabase():
    try:
        url = st.secrets["SUPABASE_URL"]
        key = st.secrets["SUPABASE_KEY"]
        return create_client(url, key)
    except Exception as e:
        logger.error(f"Supabase init failed: {e}")
        return None

supabase = get_supabase()

def read_logs():
    """Reads basic system logs depending on OS."""
    system = platform.system().lower()
    logs = []

    try:
        if "windows" in system:
            os.system("wevtutil qe System /c:5 /f:text > system_logs.txt")
            with open("system_logs.txt", "r", errors="ignore") as f:
                logs = f.readlines()[-5:]
        elif "linux" in system or "darwin" in system:
            os.system("dmesg | tail -n 5 > system_logs.txt")
            with open("system_logs.txt", "r", errors="ignore") as f:
                logs = f.readlines()
    except Exception as e:
        logger.error(f"Log read error: {e}")

    return logs

def send_logs_to_supabase():
    """Uploads recent logs to Supabase alerts table."""
    logs = read_logs()
    if not logs:
        return

    try:
        records = [{
            "source": platform.node(),
            "timestamp": datetime.utcnow().isoformat(),
            "message": log.strip(),
            "severity": "info"
        } for log in logs]

        supabase.table("alerts").insert(records).execute()
        logger.info(f"🧠 {len(records)} logs sent to Supabase.")
    except Exception as e:
        logger.error(f"Failed to send logs: {e}")

def start_sensor():
    """Runs a background sensor that uploads logs every minute."""
    st.session_state["sensor_running"] = True

    import threading

    def loop():
        while st.session_state.get("sensor_running", False):
            send_logs_to_supabase()
            time.sleep(60)  # every 60 seconds

    threading.Thread(target=loop, daemon=True).start()
    st.success("🛰️ Sensor started and sending data to cloud.")

def stop_sensor():
    st.session_state["sensor_running"] = False
    st.warning("🛑 Sensor stopped.")
