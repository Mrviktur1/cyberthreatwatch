import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json

class DataProcessor:
    def __init__(self):
        pass
    
    def parse_timestamp(self, timestamp_str, format="%Y-%m-%d %H:%M:%S"):
        """Parse timestamp string to datetime object"""
        try:
            return datetime.strptime(timestamp_str, format)
        except ValueError:
            return datetime.now()
    
    def normalize_data(self, data, mapping):
        """Normalize data based on field mapping"""
        normalized = {}
        for target_field, source_field in mapping.items():
            if source_field in data:
                normalized[target_field] = data[source_field]
            else:
                normalized[target_field] = None
        return normalized
    
    def filter_by_time_range(self, data, time_field, start_time, end_time):
        """Filter data by time range"""
        filtered_data = []
        for item in data:
            if start_time <= item[time_field] <= end_time:
                filtered_data.append(item)
        return filtered_data
    
    def aggregate_events(self, data, interval='1H'):
        """Aggregate events by time interval"""
        if not data:
            return []
            
        df = pd.DataFrame(data)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df.set_index('timestamp', inplace=True)
        
        aggregated = df.resample(interval).count()
        return aggregated.to_dict('records')
    
    def calculate_statistics(self, data):
        """Calculate basic statistics for data"""
        if not data:
            return {}
            
        df = pd.DataFrame(data)
        stats = {
            'total_events': len(data),
            'start_time': df['timestamp'].min(),
            'end_time': df['timestamp'].max(),
            'unique_sources': df['source'].nunique() if 'source' in df.columns else 0
        }
        return stats