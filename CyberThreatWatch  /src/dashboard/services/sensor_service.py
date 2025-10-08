# dashboard/services/sensor_service.py
import streamlit as st
import threading
import time
import logging
from dashboard.services.sensor import send_logs_to_supabase

logger = logging.getLogger(__name__)

class SensorService:
    """Controller that manages the lifecycle of the background log sensor."""

    def __init__(self):
        self.thread = None
        self.running = False
        self.interval = 60  # seconds between log uploads

    def _sensor_loop(self):
        """Background loop that continuously reads and uploads logs."""
        logger.info("🚀 Sensor loop started.")
        while self.running:
            try:
                send_logs_to_supabase()
            except Exception as e:
                logger.error(f"Sensor loop error: {e}")
            time.sleep(self.interval)
        logger.info("🛑 Sensor loop stopped.")

    def start(self):
        """Start the background sensor thread."""
        if self.running:
            logger.warning("Sensor already running — skipping start.")
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
            return

        self.running = False
        st.session_state["sensor_status"] = "stopped"
        st.toast("🛑 Sensor stopped.")
        logger.info("SensorService: sensor stopped manually.")

    def status(self):
        """Return current status of the sensor."""
        if self.running:
            return "active"
        return "stopped"


# Singleton pattern — so only one instance exists across Streamlit reruns
@st.cache_resource
def get_sensor_service():
    return SensorService()


sensor_service = get_sensor_service()
