import streamlit as st
import threading
import time
import logging
from dashboard.services.sensor import send_logs_to_supabase, read_logs

logger = logging.getLogger(__name__)

class SensorService:
    """Controller that manages the lifecycle of the background log sensor."""

    def __init__(self):
        self.thread = None
        self.running = False
        self.interval = 60  # interval in seconds
        self.last_run_time = None
        self.last_logs = []

    def _sensor_loop(self):
        """Continuously read logs and send to Supabase."""
        logger.info("🚀 Sensor loop started.")
        while self.running:
            try:
                self.last_logs = read_logs()
                send_logs_to_supabase()
                self.last_run_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                logger.info(f"📡 Sensor sent logs at {self.last_run_time}")
            except Exception as e:
                logger.error(f"Sensor loop error: {e}")
            time.sleep(self.interval)

        logger.info("🛑 Sensor loop stopped.")

    def start(self):
        """Start the background sensor thread."""
        if self.running:
            logger.warning("Sensor already running — skipping start.")
            st.toast("⚙️ Sensor is already running.")
            return

        self.running = True
        self.thread = threading.Thread(target=self._sensor_loop, daemon=True)
        self.thread.start()

        st.session_state["sensor_status"] = "active"
        st.toast("🛰️ Real-time sensor started.")
        logger.info("✅ SensorService: sensor started successfully.")

    def stop(self):
        """Stop the background sensor thread."""
        if not self.running:
            logger.warning("Sensor already stopped.")
            st.toast("⚠️ Sensor is already stopped.")
            return

        self.running = False
        st.session_state["sensor_status"] = "stopped"
        st.toast("🛑 Sensor stopped.")
        logger.info("SensorService: sensor stopped manually.")

    def status(self):
        """Return current status of the sensor."""
        return "active" if self.running else "stopped"

    def get_last_report(self):
        """Return the last collected logs and timestamp."""
        return {
            "status": self.status(),
            "last_run": self.last_run_time,
            "last_logs": self.last_logs[-5:] if self.last_logs else ["No logs collected yet."],
        }


# Singleton — one instance across Streamlit reruns
@st.cache_resource
def get_sensor_service():
    return SensorService()


sensor_service = get_sensor_service()
