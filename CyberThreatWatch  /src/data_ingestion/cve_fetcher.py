import requests
import pandas as pd
from datetime import datetime, timedelta

def fetch_recent_cves(api_key=None, days=7, max_results=50):
    """
    Fetches recent CVEs from NVD API with error handling
    Returns: DataFrame with columns [CVE_ID, Description, Severity, Published]
    """
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
        params = {
            "pubStartDate": (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S:000 UTC-00:00"),
            "resultsPerPage": max_results
        }
        headers = {"apiKey": api_key} if api_key else {}
        
        response = requests.get(url, params=params, headers=headers, timeout=10)
        response.raise_for_status()  # Raises HTTPError for bad status codes
        
        data = response.json()
        if not data.get("result", {}).get("CVE_Items"):
            return pd.DataFrame()  # Empty if no CVEs
            
        return pd.DataFrame([
            {
                "CVE_ID": item["cve"]["CVE_data_meta"]["ID"],
                "Description": item["cve"]["description"]["description_data"][0]["value"],
                "Severity": item["impact"].get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity", "UNKNOWN"),
                "Published": item["publishedDate"][:10]  # YYYY-MM-DD format
            }
            for item in data["result"]["CVE_Items"]
        ])
        
    except Exception as e:
        print(f"NVD API Error: {str(e)}")
        return pd.DataFrame()  # Return empty DataFrame on failure