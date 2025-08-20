# src/data_ingestion/otx_client.py
import pandas as pd
from OTXv2 import OTXv2

def get_pulse_indicators(api_key):
    otx = OTXv2(api_key)
    pulses = otx.getall()
    return pd.DataFrame([
        {
            "Type": pulse["name"],
            "Indicator": indicator["indicator"],
            "Risk": pulse["malware_families"][0] if pulse["malware_families"] else "Unknown"
        }
        for pulse in pulses
        for indicator in pulse["indicators"]
    ])