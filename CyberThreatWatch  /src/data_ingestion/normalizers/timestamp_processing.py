from datetime import datetime, timezone, timedelta
import re
from typing import Dict, Any, Optional

class TimestampProcessor:
    def __init__(self):
        # Common timestamp formats
        self.timestamp_formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y/%m/%d %H:%M:%S',
            '%d/%m/%Y %H:%M:%S',
            '%b %d %H:%M:%S',  # Syslog format without year
            '%a %b %d %H:%M:%S %Y',  # Apache format
            '%d-%b-%Y %H:%M:%S',
            '%Y%m%d%H%M%S'
        ]
        
        # Timezone offsets
        self.timezone_offsets = {
            'UTC': 0,
            'GMT': 0,
            'EST': -5,
            'EDT': -4,
            'CST': -6,
            'CDT': -5,
            'PST': -8,
            'PDT': -7
        }
    
    def parse_timestamp(self, timestamp_str: str, 
                       reference_time: Optional[datetime] = None) -> Optional[datetime]:
        """Parse timestamp string to datetime object"""
        if not timestamp_str:
            return None
        
        # Try ISO format first
        try:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except ValueError:
            pass
        
        # Try various formats
        for fmt in self.timestamp_formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        
        # Try to handle syslog format without year
        if re.match(r'[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', timestamp_str):
            current_year = datetime.now().year
            timestamp_with_year = f"{current_year} {timestamp_str}"
            try:
                return datetime.strptime(timestamp_with_year, '%Y %b %d %H:%M:%S')
            except ValueError:
                pass
        
        # Try to extract timestamp from string using regex
        timestamp_match = re.search(
            r'(\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)', 
            timestamp_str
        )
        if timestamp_match:
            return self.parse_timestamp(timestamp_match.group(1), reference_time)
        
        # If all else fails, use reference time or current time
        return reference_time or datetime.now()
    
    def normalize_timezone(self, dt: datetime, target_timezone: str = 'UTC') -> datetime:
        """Normalize timezone to target timezone"""
        if dt.tzinfo is None:
            # Assume UTC if no timezone info
            dt = dt.replace(tzinfo=timezone.utc)
        
        if target_timezone.upper() == 'UTC':
            return dt.astimezone(timezone.utc)
        else:
            # Handle other timezones by offset
            offset_hours = self.timezone_offsets.get(target_timezone.upper(), 0)
            target_tz = timezone(timedelta(hours=offset_hours))
            return dt.astimezone(target_tz)
    
    def extract_and_normalize_timestamp(self, event: Dict[str, Any], 
                                      timestamp_fields: List[str] = None) -> Dict[str, Any]:
        """Extract timestamp from event and normalize it"""
        timestamp_fields = timestamp_fields or ['timestamp', 'time', '@timestamp', 'event_time']
        
        event = event.copy()
        parsed_timestamp = None
        
        # Look for timestamp in various fields
        for field in timestamp_fields:
            if field in event and event[field]:
                parsed_timestamp = self.parse_timestamp(str(event[field]))
                if parsed_timestamp:
                    break
        
        # If no timestamp found, try to extract from message
        if not parsed_timestamp and 'message' in event:
            parsed_timestamp = self.parse_timestamp(event['message'])
        
        # Normalize timezone to UTC
        if parsed_timestamp:
            parsed_timestamp = self.normalize_timezone(parsed_timestamp, 'UTC')
            event['normalized_timestamp'] = parsed_timestamp.isoformat()
            event['timestamp_epoch'] = int(parsed_timestamp.timestamp())
        else:
            # Use current time as fallback
            current_time = datetime.now(timezone.utc)
            event['normalized_timestamp'] = current_time.isoformat()
            event['timestamp_epoch'] = int(current_time.timestamp())
            event['timestamp_warning'] = 'timestamp_not_found'
        
        return event
    
    def calculate_time_deltas(self, events: List[Dict[str, Any]], 
                            time_field: str = 'normalized_timestamp') -> List[Dict[str, Any]]:
        """Calculate time deltas between events"""
        if not events:
            return []
        
        # Sort events by timestamp
        sorted_events = sorted(
            events, 
            key=lambda x: datetime.fromisoformat(x[time_field]) if time_field in x else datetime.min
        )
        
        # Calculate time deltas
        for i in range(1, len(sorted_events)):
            current_time = datetime.fromisoformat(sorted_events[i][time_field])
            previous_time = datetime.fromisoformat(sorted_events[i-1][time_field])
            time_delta = (current_time - previous_time).total_seconds()
            
            sorted_events[i]['time_delta_seconds'] = time_delta
            sorted_events[i]['time_delta_human'] = str(current_time - previous_time)
        
        return sorted_events