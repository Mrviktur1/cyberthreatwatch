import logging
import streamlit as st

logger = logging.getLogger(__name__)

# --- Map OTX tags/keywords → Severity ---
def map_severity_from_tags(tags):
    """
    Map OTX tags to severity levels.
    """
    if not tags:
        return "medium"

    tags_lower = [t.lower() for t in tags]

    if any(t in tags_lower for t in ["critical", "apt", "ransomware", "exploit", "cve"]):
        return "high"
    elif any(t in tags_lower for t in ["malware", "trojan", "botnet", "phishing"]):
        return "medium"
    elif any(t in tags_lower for t in ["suspicious", "info", "scanning", "reconnaissance"]):
        return "low"
    else:
        return "medium"  # default

def collect_otx_alerts(otx, supabase):
    """
    Fetch latest OTX alerts and insert them into Supabase.
    """
    if not otx:
        msg = "❌ OTX client not initialized. Check your OTX_API_KEY in st.secrets."
        logger.warning(msg)
        st.error(msg)
        return

    if not supabase:
        msg = "❌ Supabase client not initialized. Check SUPABASE_URL and SUPABASE_KEY in st.secrets."
        logger.warning(msg)
        st.error(msg)
        return

    try:
        # Fetch latest OTX pulses (example: last 5 pulses)
        results = otx.getall()
        pulses = results[:5] if results else []

        if not pulses:
            st.info("⚠️ No new OTX alerts found.")
            return

        inserted = 0
        for pulse in pulses:
            tags = pulse.get("tags", [])
            severity = map_severity_from_tags(tags)

            alert = {
                "name": pulse.get("name"),
                "description": pulse.get("description"),
                "author": pulse.get("author_name"),
                "created": pulse.get("created"),
                "severity": severity,
                "type": "OTX",
                "tags": ", ".join(tags) if tags else None,
            }
            supabase.table("alerts").insert(alert).execute()
            inserted += 1

        st.success(f"✅ Inserted {inserted} OTX alerts into Supabase.")

    except Exception as e:
        logger.error(f"OTX collection error: {e}")
        st.error(f"⚠️ Failed to fetch OTX alerts: {e}")
