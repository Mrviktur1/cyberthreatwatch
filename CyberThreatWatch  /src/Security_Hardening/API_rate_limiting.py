import time
@st.cache_data(ttl=3600)  # Refresh hourly
def get_cached_cves():
    time.sleep(2)  # Avoid API rate limits
    return fetch_recent_cves()