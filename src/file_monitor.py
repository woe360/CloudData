import pandas as pd
import json
import os
import logging
from datetime import datetime
from typing import Dict, List
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, log_file: str):
        self.log_file = log_file
        self.events = []
        # Set up logging
        self.logger = self._setup_logger()
        self._ensure_log_file()
        self.logger.info(f"FileEventHandler initialized with log file: {log_file}")
    
    def _setup_logger(self) -> logging.Logger:
        """Set up a logger for the file monitor"""
        logger = logging.getLogger('FileMonitor')
        logger.setLevel(logging.INFO)
        
        # Create handlers
        console_handler = logging.StreamHandler()
        file_handler = logging.FileHandler('file_monitor.log')
        
        # Create formatters and add it to handlers
        log_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(log_format)
        file_handler.setFormatter(log_format)
        
        # Add handlers to the logger
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
        
        return logger
    
    def _ensure_log_file(self):
        """Ensure the log file exists and has proper structure"""
        try:
            if not os.path.exists(self.log_file):
                self.logger.info(f"Creating new log file: {self.log_file}")
                self._save_events()
            else:
                # Try to load existing events
                try:
                    with open(self.log_file, 'r') as f:
                        data = json.load(f)
                        self.events = data.get('events', [])
                    self.logger.info(f"Loaded {len(self.events)} existing events")
                except json.JSONDecodeError:
                    self.logger.warning(f"Could not parse existing log file. Creating new one.")
                    self._save_events()
        except Exception as e:
            self.logger.error(f"Error in _ensure_log_file: {str(e)}")
            raise
    
    def _save_events(self):
        """Save events to log file with error handling"""
        try:
            with open(self.log_file, 'w') as f:
                json.dump({'events': self.events}, f, indent=2)
            self.logger.debug(f"Saved {len(self.events)} events to log file")
        except Exception as e:
            self.logger.error(f"Error saving events: {str(e)}")
            raise
    
    def on_any_event(self, event):
        """Handle any file system event"""
        if event.is_directory:
            return
        
        try:
            event_data = {
                'timestamp': datetime.now().timestamp(),
                'event_type': event.event_type,
                'path': event.src_path,
                'is_directory': event.is_directory
            }
            
            self.events.append(event_data)
            self._save_events()
            
            self.logger.info(
                f"Event logged - Type: {event.event_type}, "
                f"Path: {event.src_path}"
            )
        except Exception as e:
            self.logger.error(f"Error processing event: {str(e)}")
    
    def test_logging(self):
        """Test the logging functionality"""
        try:
            test_file = "test_file.txt"
            
            # Create test file
            with open(test_file, 'w') as f:
                f.write("Test content")
            self.logger.info("Created test file")
            
            # Read current log
            with open(self.log_file, 'r') as f:
                log_data = json.load(f)
                self.logger.info(f"Current log contains {len(log_data['events'])} events")
                
            return True
        except Exception as e:
            self.logger.error(f"Test logging failed: {str(e)}")
            return False

def setup_monitoring(watch_directory: str, log_file: str = 'activity_log.json'):
    """Set up file system monitoring"""
    try:
        # Set up the event handler
        event_handler = FileEventHandler(log_file)
        
        # Set up the observer
        observer = Observer()
        observer.schedule(event_handler, watch_directory, recursive=True)
        observer.start()
        
        event_handler.logger.info(f"Started monitoring directory: {watch_directory}")
        return event_handler, observer
    except Exception as e:
        logging.error(f"Error setting up monitoring: {str(e)}")
        raise

if __name__ == "__main__":
    # Quick test of the monitoring system
    try:
        handler, observer = setup_monitoring(".")
        print("Monitoring started. Press Ctrl+C to stop.")
        
        # Run a quick test
        if handler.test_logging():
            print("Logging test successful")
        
        try:
            while True:
                pass
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
        
    except Exception as e:
        print(f"Error: {str(e)}")