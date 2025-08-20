import csv
from datetime import datetime
from io import StringIO

class CSVParser:
    def __init__(self):
        pass
    
    def parse(self, csv_line, fieldnames=None):
        """Parse a CSV line"""
        try:
            # Use StringIO to simulate file-like object
            f = StringIO(csv_line)
            reader = csv.DictReader(f, fieldnames=fieldnames)
            
            row = next(reader)
            parsed = {
                'timestamp': row.get('timestamp', row.get('time', datetime.now())),
                'message': row.get('message', str(row)),
                'source': row.get('source', row.get('host', 'unknown')),
                'raw': csv_line
            }
            
            # Add all fields
            for key, value in row.items():
                if key not in parsed:
                    parsed[key] = value
            
            return parsed
        except Exception as e:
            return {
                'timestamp': datetime.now(),
                'message': f"CSV parsing error: {str(e)}",
                'source': 'parser',
                'raw': csv_line
            }
    
    def parse_file(self, file_path, has_header=True):
        """Parse a complete CSV file"""
        results = []
        with open(file_path, 'r', newline='') as f:
            if has_header:
                reader = csv.DictReader(f)
            else:
                reader = csv.reader(f)
                # Use generic field names if no header
                fieldnames = [f'field_{i}' for i in range(100)]  # Assume max 100 columns
                
            for row in reader:
                if has_header:
                    parsed_row = {
                        'timestamp': row.get('timestamp', row.get('time', datetime.now())),
                        'message': row.get('message', str(row)),
                        'source': row.get('source', row.get('host', 'unknown')),
                        'raw': str(row)
                    }
                else:
                    parsed_row = {
                        'timestamp': datetime.now(),
                        'message': ' '.join(row),
                        'source': 'unknown',
                        'raw': str(row)
                    }
                
                # Add all fields
                for key, value in (row.items() if has_header else enumerate(row)):
                    parsed_row[key] = value
                
                results.append(parsed_row)
        
        return results