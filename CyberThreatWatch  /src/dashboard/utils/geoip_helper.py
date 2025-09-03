import geoip2.database
import os
import logging

logger = logging.getLogger(__name__)

DB_PATH = os.path.join("data", "GeoLite2-City.mmdb")

def ip_to_location(ip: str):
    """Convert an IP to (lat, lon, country) using MaxMind GeoLite2"""
    try:
        if not os.path.exists(DB_PATH):
            logger.error("GeoLite2 database not found.")
            return None

        with geoip2.database.Reader(DB_PATH) as reader:
            response = reader.city(ip)
            return {
                "ip": ip,
                "lat": response.location.latitude,
                "lon": response.location.longitude,
                "country": response.country.name
            }
    except Exception as e:
        logger.warning(f"GeoIP lookup failed for {ip}: {e}")
        return None
