# dashboard/services/data_service.py
import streamlit as st
from supabase import create_client, Client
import logging
import json
import threading
import time

logger = logging.getLogger(__name__)

@st.cache_resource
def get_supabase() -> Client:
    """Initialize Supabase client."""
    try:
        url = st.secrets["SUPABASE_URL"]
        key = st.secrets["SUPABASE_KEY"]
        client = create_client(url, key)
        logger.info("✅ Supabase connected in data_service.py")
        return client
    except Exception as e:
        logger.error(f"Supabase init error: {e}")
        return None

supabase = get_supabase()

class RealtimeData:
    def __init__(self):
        self.listeners = []
        self.running = False
        self.data_cache = []

    def subscribe(self, callback):
        """Register a new callback for realtime updates."""
        self.listeners.append(callback)

    def notify(self, data):
        """Notify all listeners with fresh data."""
        for cb in self.listeners:
            try:
                cb(data)
            except Exception as e:
                logger.error(f"Callback error: {e}")

    def fetch_data(self):
        """Fetch alerts from Supabase."""
        try:
            res = supabase.table("alerts").select("*").order("timestamp", desc=True).limit(20).execute()
            data = res.data or []
            if data != self.data_cache:
                self.data_cache = data
                self.notify(data)
        except Exception as e:
            logger.error(f"Fetch error: {e}")

    def start_realtime(self, interval=5):
        """Start a background thread that polls data every few seconds."""
        if self.running:
            return
        self.running = True

        def loop():
            while self.running:
                self.fetch_data()
                time.sleep(interval)

        threading.Thread(target=loop, daemon=True).start()
        logger.info("📡 Realtime data thread started")

    def stop_realtime(self):
        self.running = False
        logger.info("🛑 Realtime data thread stopped")


# Create a shared instance
data_stream = RealtimeData()