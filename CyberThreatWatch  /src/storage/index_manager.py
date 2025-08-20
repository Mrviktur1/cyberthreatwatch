import sqlite3
from typing import List, Dict, Any
import threading
import time

class IndexManager:
    def __init__(self, db_path: str = "cyberthreatwatch.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._initialize_indexes()
    
    def _initialize_indexes(self):
        """Create initial indexes for better performance"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Index on events timestamp
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_events_timestamp 
                ON events(timestamp)
            ''')
            
            # Index on events event_type
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_events_event_type 
                ON events(event_type)
            ''')
            
            # Index on events source
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_events_source 
                ON events(source)
            ''')
            
            # Index on events severity
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_events_severity 
                ON events(severity)
            ''')
            
            # Index on alerts timestamp
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp 
                ON alerts(timestamp)
            ''')
            
            # Index on alerts severity
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_alerts_severity 
                ON alerts(severity)
            ''')
            
            # Index on IOCs
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_iocs_type_value 
                ON iocs(ioc_type, ioc_value)
            ''')
            
            # Index on IOCs threat_level
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_iocs_threat_level 
                ON iocs(threat_level)
            ''')
            
            conn.commit()
            conn.close()
    
    def get_index_stats(self) -> Dict[str, Any]:
        """Get statistics about database indexes"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get index information
            cursor.execute('''
                SELECT name, tbl_name, sql 
                FROM sqlite_master 
                WHERE type = 'index'
            ''')
            
            indexes = []
            for row in cursor.fetchall():
                indexes.append({
                    'name': row[0],
                    'table': row[1],
                    'sql': row[2]
                })
            
            # Get index usage statistics (SQLite doesn't have built-in usage stats)
            # We'll simulate by checking if queries are using indexes
            
            conn.close()
            
            return {
                'total_indexes': len(indexes),
                'indexes': indexes
            }
    
    def optimize_indexes(self):
        """Optimize database indexes"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Analyze for better query planning
            cursor.execute("ANALYZE")
            
            # Rebuild all indexes
            cursor.execute("REINDEX")
            
            conn.commit()
            conn.close()
    
    def create_custom_index(self, table: str, columns: List[str], 
                          index_name: str = None) -> bool:
        """Create a custom index on specified table and columns"""
        if not index_name:
            index_name = f"idx_{table}_{'_'.join(columns)}"
        
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            try:
                columns_str = ", ".join(columns)
                cursor.execute(f'''
                    CREATE INDEX IF NOT EXISTS {index_name} 
                    ON {table}({columns_str})
                ''')
                
                conn.commit()
                conn.close()
                return True
                
            except Exception as e:
                print(f"Error creating index: {e}")
                conn.close()
                return False
    
    def drop_index(self, index_name: str) -> bool:
        """Drop an existing index"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            try:
                cursor.execute(f"DROP INDEX IF EXISTS {index_name}")
                conn.commit()
                conn.close()
                return True
                
            except Exception as e:
                print(f"Error dropping index: {e}")
                conn.close()
                return False

class QueryOptimizer:
    def __init__(self, db_path: str):
        self.db_path = db_path
    
    def explain_query(self, query: str, params: tuple = None) -> List[Dict[str, Any]]:
        """Explain query execution plan"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if params:
            cursor.execute(f"EXPLAIN QUERY PLAN {query}", params)
        else:
            cursor.execute(f"EXPLAIN QUERY PLAN {query}")
        
        explanation = []
        for row in cursor.fetchall():
            explanation.append({
                'id': row[0],
                'parent': row[1],
                'notused': row[2],
                'detail': row[3]
            })
        
        conn.close()
        return explanation
    
    def suggest_indexes(self, query: str) -> List[Dict[str, Any]]:
        """Suggest indexes for a query"""
        explanation = self.explain_query(query)
        suggestions = []
        
        for line in explanation:
            detail = line['detail']
            
            # Look for SCAN TABLE in explanation
            if 'SCAN TABLE' in detail and 'USING INDEX' not in detail:
                # Extract table name
                table_start = detail.find('SCAN TABLE ') + len('SCAN TABLE ')
                table_end = detail.find(' ', table_start)
                table_name = detail[table_start:table_end]
                
                # Look for WHERE clauses that might benefit from indexes
                if 'WHERE' in detail:
                    where_start = detail.find('WHERE') + len('WHERE')
                    where_clause = detail[where_start:].strip()
                    
                    # Simple heuristic: index columns used in WHERE
                    # This is very basic and would need more sophisticated parsing
                    if '=' in where_clause:
                        column = where_clause.split('=')[0].strip()
                        suggestions.append({
                            'table': table_name,
                            'columns': [column],
                            'reason': f'WHERE clause filtering on {column}'
                        })
        
        return suggestions
    
    def benchmark_query(self, query: str, params: tuple = None, 
                       iterations: int = 10) -> Dict[str, Any]:
        """Benchmark query performance"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        times = []
        for _ in range(iterations):
            start_time = time.time()
            
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            cursor.fetchall()  # Ensure we read all results
            end_time = time.time()
            
            times.append(end_time - start_time)
        
        conn.close()
        
        return {
            'query': query,
            'iterations': iterations,
            'min_time': min(times),
            'max_time': max(times),
            'avg_time': sum(times) / len(times),
            'total_time': sum(times)
        }