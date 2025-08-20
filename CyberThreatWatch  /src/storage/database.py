import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
import threading

class DatabaseManager:
    def __init__(self, db_path: str = "cyberthreatwatch.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize database with required tables"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT,
                    source TEXT,
                    message TEXT,
                    raw_data TEXT,
                    severity TEXT,
                    normalized INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    rule_id TEXT,
                    rule_name TEXT,
                    severity TEXT,
                    message TEXT,
                    source_ip TEXT,
                    dest_ip TEXT,
                    event_count INTEGER,
                    details TEXT,
                    acknowledged INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # IOC table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_type TEXT NOT NULL,
                    ioc_value TEXT NOT NULL,
                    source TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    threat_level TEXT,
                    description TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(ioc_type, ioc_value)
                )
            ''')
            
            # Config table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS config (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
    
    def store_event(self, event: Dict[str, Any]) -> int:
        """Store an event in the database"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO events (timestamp, event_type, source, message, raw_data, severity, normalized)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.get('timestamp'),
                event.get('event_type'),
                event.get('source'),
                event.get('message'),
                json.dumps(event) if isinstance(event, dict) else str(event),
                event.get('severity', 'info'),
                1 if event.get('normalized') else 0
            ))
            
            event_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return event_id
    
    def bulk_store_events(self, events: List[Dict[str, Any]]) -> List[int]:
        """Store multiple events efficiently"""
        event_ids = []
        
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for event in events:
                cursor.execute('''
                    INSERT INTO events (timestamp, event_type, source, message, raw_data, severity, normalized)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event.get('timestamp'),
                    event.get('event_type'),
                    event.get('source'),
                    event.get('message'),
                    json.dumps(event) if isinstance(event, dict) else str(event),
                    event.get('severity', 'info'),
                    1 if event.get('normalized') else 0
                ))
                
                event_ids.append(cursor.lastrowid)
            
            conn.commit()
            conn.close()
        
        return event_ids
    
    def store_alert(self, alert: Dict[str, Any]) -> int:
        """Store an alert in the database"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO alerts (timestamp, rule_id, rule_name, severity, message, source_ip, dest_ip, event_count, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert.get('timestamp', datetime.now().isoformat()),
                alert.get('rule_id'),
                alert.get('rule_name'),
                alert.get('severity', 'medium'),
                alert.get('message'),
                alert.get('source_ip'),
                alert.get('dest_ip'),
                alert.get('event_count', 1),
                json.dumps(alert.get('details', {}))
            ))
            
            alert_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return alert_id
    
    def get_events(self, limit: int = 100, offset: int = 0, 
                  filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Retrieve events from database with optional filtering"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = "SELECT * FROM events WHERE 1=1"
            params = []
            
            if filters:
                if 'start_time' in filters:
                    query += " AND timestamp >= ?"
                    params.append(filters['start_time'])
                
                if 'end_time' in filters:
                    query += " AND timestamp <= ?"
                    params.append(filters['end_time'])
                
                if 'event_type' in filters:
                    query += " AND event_type = ?"
                    params.append(filters['event_type'])
                
                if 'severity' in filters:
                    query += " AND severity = ?"
                    params.append(filters['severity'])
                
                if 'source' in filters:
                    query += " AND source LIKE ?"
                    params.append(f'%{filters["source"]}%')
            
            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            events = []
            for row in rows:
                event = dict(row)
                # Parse raw_data if it exists
                if event.get('raw_data'):
                    try:
                        event['raw_data'] = json.loads(event['raw_data'])
                    except:
                        pass
                events.append(event)
            
            conn.close()
            return events
    
    def get_event_count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """Get count of events matching filters"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = "SELECT COUNT(*) FROM events WHERE 1=1"
            params = []
            
            if filters:
                if 'start_time' in filters:
                    query += " AND timestamp >= ?"
                    params.append(filters['start_time'])
                
                if 'end_time' in filters:
                    query += " AND timestamp <= ?"
                    params.append(filters['end_time'])
                
                if 'event_type' in filters:
                    query += " AND event_type = ?"
                    params.append(filters['event_type'])
            
            cursor.execute(query, params)
            count = cursor.fetchone()[0]
            conn.close()
            
            return count
    
    def update_ioc(self, ioc_type: str, ioc_value: str, 
                  source: str, threat_level: str = 'unknown') -> bool:
        """Update or insert an IOC"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if IOC exists
            cursor.execute(
                "SELECT id FROM iocs WHERE ioc_type = ? AND ioc_value = ?",
                (ioc_type, ioc_value)
            )
            
            existing = cursor.fetchone()
            now = datetime.now().isoformat()
            
            if existing:
                # Update existing IOC
                cursor.execute('''
                    UPDATE iocs 
                    SET last_seen = ?, threat_level = ?, source = ?
                    WHERE id = ?
                ''', (now, threat_level, source, existing[0]))
            else:
                # Insert new IOC
                cursor.execute('''
                    INSERT INTO iocs (ioc_type, ioc_value, source, first_seen, last_seen, threat_level)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (ioc_type, ioc_value, source, now, now, threat_level))
            
            conn.commit()
            conn.close()
            return True
    
    def get_iocs(self, ioc_type: Optional[str] = None, 
                threat_level: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve IOCs from database"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = "SELECT * FROM iocs WHERE 1=1"
            params = []
            
            if ioc_type:
                query += " AND ioc_type = ?"
                params.append(ioc_type)
            
            if threat_level:
                query += " AND threat_level = ?"
                params.append(threat_level)
            
            query += " ORDER BY last_seen DESC"
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            iocs = [dict(row) for row in rows]
            conn.close()
            
            return iocs

class DatabaseMaintenance:
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
    
    def cleanup_old_events(self, days_to_keep: int = 30):
        """Clean up events older than specified days"""
        with self.db_manager.lock:
            conn = sqlite3.connect(self.db_manager.db_path)
            cursor = conn.cursor()
            
            cutoff_date = (datetime.now() - timedelta(days=days_to_keep)).isoformat()
            
            cursor.execute("DELETE FROM events WHERE timestamp < ?", (cutoff_date,))
            deleted_count = cursor.rowcount
            
            conn.commit()
            conn.close()
            
            return deleted_count
    
    def optimize_database(self):
        """Optimize database performance"""
        with self.db_manager.lock:
            conn = sqlite3.connect(self.db_manager.db_path)
            cursor = conn.cursor()
            
            # Vacuum to defragment database
            cursor.execute("VACUUM")
            
            # Rebuild indexes
            cursor.execute("REINDEX")
            
            conn.commit()
            conn.close()
    
    def backup_database(self, backup_path: str):
        """Create a backup of the database"""
        import shutil
        with self.db_manager.lock:
            shutil.copy2(self.db_manager.db_path, backup_path)