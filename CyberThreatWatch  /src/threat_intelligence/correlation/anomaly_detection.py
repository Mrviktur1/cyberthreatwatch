import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from datetime import datetime, timedelta
from typing import List, Dict, Any
import pandas as pd

class AnomalyDetector:
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.normal_profiles = {}
    
    def detect_volume_anomalies(self, events: List[Dict[str, Any]], 
                               time_window: str = '1H') -> List[Dict[str, Any]]:
        """Detect anomalies in event volumes"""
        if not events:
            return []
        
        # Convert to DataFrame
        df = pd.DataFrame(events)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Resample by time window
        volume_series = df.resample(time_window, on='timestamp').size()
        
        # Calculate statistics
        mean_volume = volume_series.mean()
        std_volume = volume_series.std()
        
        anomalies = []
        for timestamp, volume in volume_series.items():
            if volume > mean_volume + 2 * std_volume:  > 2 standard deviations
                anomalies.append({
                    'type': 'volume_anomaly',
                    'timestamp': timestamp.isoformat(),
                    'volume': volume,
                    'mean_volume': mean_volume,
                    'std_volume': std_volume,
                    'z_score': (volume - mean_volume) / std_volume,
                    'severity': 'high' if volume > mean_volume + 3 * std_volume else 'medium'
                })
        
        return anomalies
    
    def detect_source_anomalies(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect anomalies in source behavior"""
        if not events:
            return []
        
        # Group by source IP
        source_stats = {}
        for event in events:
            source_ip = event.get('source_ip', 'unknown')
            if source_ip not in source_stats:
                source_stats[source_ip] = {
                    'count': 0,
                    'destinations': set(),
                    'event_types': set()
                }
            
            source_stats[source_ip]['count'] += 1
            if 'dest_ip' in event:
                source_stats[source_ip]['destinations'].add(event['dest_ip'])
            if 'event_type' in event:
                source_stats[source_ip]['event_types'].add(event['event_type'])
        
        # Calculate statistics
        counts = [stats['count'] for stats in source_stats.values()]
        mean_count = np.mean(counts) if counts else 0
        std_count = np.std(counts) if counts else 0
        
        anomalies = []
        for source_ip, stats in source_stats.items():
            # Check for unusual activity volume
            if std_count > 0 and stats['count'] > mean_count + 2 * std_count:
                anomalies.append({
                    'type': 'source_volume_anomaly',
                    'source_ip': source_ip,
                    'count': stats['count'],
                    'mean_count': mean_count,
                    'std_count': std_count,
                    'z_score': (stats['count'] - mean_count) / std_count,
                    'severity': 'high'
                })
            
            # Check for scanning behavior (many destinations)
            if len(stats['destinations']) > 10:  # Threshold
                anomalies.append({
                    'type': 'source_scanning_anomaly',
                    'source_ip': source_ip,
                    'destination_count': len(stats['destinations']),
                    'event_count': stats['count'],
                    'severity': 'medium'
                })
        
        return anomalies
    
    def train_isolation_forest(self, features: np.ndarray, feature_names: List[str], 
                             model_name: str = 'default'):
        """Train Isolation Forest model for anomaly detection"""
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)
        
        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(features_scaled)
        
        self.models[model_name] = model
        self.scalers[model_name] = scaler
        
        return model
    
    def detect_with_isolation_forest(self, features: np.ndarray, 
                                   feature_names: List[str], 
                                   model_name: str = 'default') -> List[int]:
        """Detect anomalies using Isolation Forest"""
        if model_name not in self.models:
            self.train_isolation_forest(features, feature_names, model_name)
        
        features_scaled = self.scalers[model_name].transform(features)
        predictions = self.models[model_name].predict(features_scaled)
        
        # Convert predictions: -1 = anomaly, 1 = normal
        return [1 if pred == -1 else 0 for pred in predictions]
    
    def create_behavioral_profile(self, events: List[Dict[str, Any]], 
                                entity_type: str, entity_id: str):
        """Create normal behavioral profile for an entity"""
        if not events:
            return
        
        # Extract features for profiling
        features = self._extract_behavioral_features(events)
        
        # Store profile
        if entity_type not in self.normal_profiles:
            self.normal_profiles[entity_type] = {}
        
        self.normal_profiles[entity_type][entity_id] = {
            'features': features,
            'last_updated': datetime.now(),
            'event_count': len(events)
        }
    
    def detect_behavioral_anomalies(self, current_events: List[Dict[str, Any]], 
                                  entity_type: str, entity_id: str) -> List[Dict[str, Any]]:
        """Detect behavioral anomalies compared to normal profile"""
        if (entity_type not in self.normal_profiles or 
            entity_id not in self.normal_profiles[entity_type]):
            return []
        
        profile = self.normal_profiles[entity_type][entity_id]
        current_features = self._extract_behavioral_features(current_events)
        
        # Simple comparison (would use more sophisticated statistical tests)
        anomalies = []
        
        # Compare event counts
        current_count = len(current_events)
        normal_count = profile['event_count']
        
        if current_count > normal_count * 2:  # Double the normal activity
            anomalies.append({
                'type': 'behavioral_volume_anomaly',
                'entity_type': entity_type,
                'entity_id': entity_id,
                'current_count': current_count,
                'normal_count': normal_count,
                'ratio': current_count / normal_count,
                'severity': 'medium'
            })
        
        return anomalies
    
    def _extract_behavioral_features(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract features for behavioral analysis"""
        if not events:
            return {}
        
        # Basic features
        features = {
            'total_events': len(events),
            'unique_destinations': len(set(e.get('dest_ip', '') for e in events)),
            'unique_event_types': len(set(e.get('event_type', '') for e in events)),
            'avg_event_size': np.mean([e.get('bytes', 0) for e in events]) if events else 0
        }
        
        # Time-based features
        timestamps = [datetime.fromisoformat(e['timestamp']) for e in events if 'timestamp' in e]
        if timestamps:
            time_diffs = [(timestamps[i] - timestamps[i-1]).total_seconds() 
                         for i in range(1, len(timestamps))]
            features['avg_time_between_events'] = np.mean(time_diffs) if time_diffs else 0
        
        return features

class RealTimeAnomalyDetector:
    def __init__(self, window_size: int = 100, slide_interval: int = 10):
        self.window_size = window_size
        self.slide_interval = slide_interval
        self.event_window = []
        self.detector = AnomalyDetector()
    
    def add_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Add event and check for anomalies"""
        self.event_window.append(event)
        
        # Maintain window size
        if len(self.event_window) > self.window_size:
            self.event_window = self.event_window[-self.window_size:]
        
        # Check for anomalies at slide intervals
        if len(self.event_window) % self.slide_interval == 0:
            return self.detect_anomalies()
        
        return []
    
    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """Detect anomalies in current window"""
        anomalies = []
        
        # Volume anomalies
        volume_anomalies = self.detector.detect_volume_anomalies(self.event_window, '1M')
        anomalies.extend(volume_anomalies)
        
        # Source anomalies
        source_anomalies = self.detector.detect_source_anomalies(self.event_window)
        anomalies.extend(source_anomalies)
        
        return anomalies