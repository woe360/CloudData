# monitor.py
import os
import time
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging
import pandas as pd
from datetime import datetime
from pathlib import Path
import sqlite3
import threading

class RansomwareDetector:
    def __init__(self, watch_directory, db_file='src/activity.db'):
        self.watch_directory = watch_directory
        self.db_file = db_file
        self.alert_threshold = 10
        self.suspicious_extensions = {'.encrypted', '.crypto', '.locked', '.decrypt'}
        self.lock = threading.Lock()
        
        # Set up logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger('RansomwareDetector')
        
        # Initialize database
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database for storing events"""
        try:
            os.makedirs(os.path.dirname(self.db_file), exist_ok=True)
            with sqlite3.connect(self.db_file) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL,
                        event_time TEXT,
                        event_type TEXT,
                        src_ip TEXT,
                        dst_ip TEXT,
                        src_port INTEGER,
                        dst_port INTEGER,
                        command TEXT,
                        operation TEXT,
                        path TEXT,
                        query TEXT
                    )
                ''')
                conn.commit()
        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")

    def add_event(self, event):
        """Add a single event to the database"""
        try:
            with self.lock:
                with sqlite3.connect(self.db_file) as conn:
                    conn.execute('''
                        INSERT INTO events (
                            timestamp, event_time, event_type, src_ip, dst_ip,
                            src_port, dst_port, command, operation, path, query
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        event.get('timestamp'),
                        event.get('event_time'),
                        event.get('event_type'),
                        event.get('src_ip'),
                        event.get('dst_ip'),
                        event.get('src_port'),
                        event.get('dst_port'),
                        event.get('command'),
                        event.get('operation'),
                        event.get('path'),
                        event.get('query')
                    ))
                    conn.commit()
        except Exception as e:
            self.logger.error(f"Error adding event to database: {e}")

    def get_events(self, limit=1000):
        """Get events from database as pandas DataFrame"""
        try:
            with sqlite3.connect(self.db_file) as conn:
                return pd.read_sql_query(
                    'SELECT * FROM events ORDER BY timestamp DESC LIMIT ?',
                    conn,
                    params=(limit,)
                )
        except Exception as e:
            self.logger.error(f"Error getting events from database: {e}")
            return pd.DataFrame()

    def extract_ip_port(self, ip_port_str):
        """Safely extract IP and port from string"""
        try:
            if ':' in ip_port_str:
                ip, port = ip_port_str.split(':')
                return ip, int(port)
            return ip_port_str, None
        except Exception:
            return ip_port_str, None

    def process_log_line(self, line, log_type):
        """Process a single log line based on type"""
        try:
            if not line.strip() or line.startswith('Timestamp') or 'IP_src' in line:
                return None

            fields = line.strip().split()
            if not fields:
                return None

            try:
                timestamp = float(fields[0])
            except ValueError:
                return None

            event = {
                'timestamp': timestamp,
                'event_time': datetime.fromtimestamp(timestamp).isoformat()
            }

            if log_type == "TCPconnInfo.txt":
                src_ip, src_port = self.extract_ip_port(fields[1])
                dst_ip, dst_port = self.extract_ip_port(fields[2])
                
                event.update({
                    'event_type': 'network',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'command': fields[3] if len(fields) > 3 else None
                })
            elif log_type == "IOops.txt":
                event.update({
                    'event_type': 'filesystem',
                    'operation': fields[1] if len(fields) > 1 else None,
                    'path': ' '.join(fields[2:]) if len(fields) > 2 else None
                })
            elif log_type == "DNSinfo.txt":
                src_ip, _ = self.extract_ip_port(fields[1])
                dst_ip, _ = self.extract_ip_port(fields[2])
                
                event.update({
                    'event_type': 'dns',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'query': fields[4] if len(fields) > 4 else None
                })
            
            return event
            
        except Exception as e:
            self.logger.error(f"Error processing log line: {e}")
            return None

    def process_log_file(self, file_path):
        """Process a log file and add events to database"""
        encodings = ['utf-8', 'latin1', 'cp1252', 'iso-8859-1']
        
        for encoding in encodings:
            try:
                log_type = os.path.basename(file_path)
                with open(file_path, 'r', encoding=encoding) as f:
                    next(f, None)  # Skip header
                    
                    for line in f:
                        event = self.process_log_line(line, log_type)
                        if event:
                            self.add_event(event)
                return  # If successful, exit the encoding loop
                
            except UnicodeDecodeError:
                continue
            except Exception as e:
                self.logger.error(f"Error processing log file {file_path} with {encoding}: {e}")

    def check_suspicious_activity(self, event):
        """Check for suspicious activity patterns"""
        try:
            with sqlite3.connect(self.db_file) as conn:
                # Check recent activity
                recent_count = conn.execute('''
                    SELECT COUNT(*) FROM events 
                    WHERE timestamp > ?
                ''', (time.time() - 60,)).fetchone()[0]
                
                if recent_count > self.alert_threshold:
                    self.logger.warning("High activity detected!")
                    return True
                    
                if event.get('event_type') == 'filesystem':
                    path = event.get('path', '')
                    _, ext = os.path.splitext(path)
                    if ext.lower() in self.suspicious_extensions:
                        self.logger.warning(f"Suspicious extension detected: {ext}")
                        return True
                        
                return False
                
        except Exception as e:
            self.logger.error(f"Error checking suspicious activity: {e}")
            return False

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, detector):
        self.detector = detector
        self._observer = None

    def handle_event(self, event, event_type):
        if event.is_directory:
            return
            
        file_name = os.path.basename(event.src_path)
        if file_name in ["TCPconnInfo.txt", "IOops.txt", "DNSinfo.txt"]:
            self.detector.process_log_file(event.src_path)

    def on_modified(self, event):
        self.handle_event(event, 'modified')

    def on_created(self, event):
        self.handle_event(event, 'created')

def setup_monitoring(watch_directory, db_file='src/activity.db'):
    """Set up the monitoring system"""
    try:
        detector = RansomwareDetector(watch_directory, db_file)
        handler = FileEventHandler(detector)
        
        observer = Observer()
        observer.schedule(handler, watch_directory, recursive=True)
        observer._handlers = {}  # Reset handlers to prevent duplicate scheduling
        observer.start()
        
        return observer, detector
        
    except Exception as e:
        logging.error(f"Error setting up monitoring: {e}")
        raise

if __name__ == "__main__":
    watch_dir = "data"
    observer, detector = setup_monitoring(watch_dir)
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()