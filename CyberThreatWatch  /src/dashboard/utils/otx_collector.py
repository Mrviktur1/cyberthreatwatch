import logging
from datetime import datetime
from OTXv2 import OTXv2

logger = logging.getLogger(__name__)


def collect_otx_alerts(otx: OTXv2, supabase):
    """Fetch latest OTX pulses and save into Supabase alerts"""
    try:
        if not otx or not supabase:
            logger.warning("OTX or Supabase not initialized")
            return

        # Fetch trending pulses (AlienVault curated feeds)
        pulses = otx.getall(iterate=True)

        for pulse in pulses:
            alert = {
                "timestamp": datetime.utcnow().isoformat(),
                "severity": "High",  # You could map based on pulse tags
                "type": pulse.get("TLP", "Threat Pulse"),
                "source_ip": None,
                "description": pulse.get("name", "OTX Pulse"),
                "status": "Open",
                "tag": "OTX"
            }

            # Insert into Supabase (ignore duplicates based on description)
            existing = supabase.table("alerts").select("*").eq("description", alert["description"]).execute()
            if not existing.data:
                supabase.table("alerts").insert(alert).execute()

        logger.info("✅ OTX alerts collected successfully")

    except Exception as e:
        logger.error(f"Error collecting OTX alerts: {e}")
