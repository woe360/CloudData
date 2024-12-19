# # file_monitor.py
# import pandas as pd
# import json
# import os
# from datetime import datetime
# from typing import Dict, List
# import logging
# from watchdog.observers import Observer
# from watchdog.events import FileSystemEventHandler

# class FileEventHandler(FileSystemEventHandler):
#     def __init__(self, log_file: str):
#         self.log_file = log_file
#         self.events = []
#         self._ensure_log_file()
    
#     def _ensure_log_file(self):
#         if not os.path.exists(self.log_file):
#             self._save_events()
    
#     def _save_events(self):
#         with open(self.log_file, 'w') as f:
#             json.dump({'events': self.events}, f)
    
#     def on_any_event(self, event):
#         if event.is_directory:
#             return
        
#         event_data = {
#             'timestamp': datetime.now().timestamp(),
#             'event_type': event.event_type,
#             'path': event.src_path,
#             'is_directory': event.is_directory
#         }
        
#         self.events.append(event_data)
#         self._save_events()

# # analyzer.py
# class RansomwareAnalyzer:
#     def __init__(self, log_file: str):
#         self.log_file = log_file
    
#     def load_data(self) -> pd.DataFrame:
#         with open(self.log_file, 'r') as f:
#             data = json.load(f)
#             df = pd.DataFrame(data['events'])
#             df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
#             return df
    
#     def calculate_metrics(self, df: pd.DataFrame) -> Dict:
#         return {
#             'total_events': len(df),
#             'events_by_type': df['event_type'].value_counts().to_dict(),
#             'file_extensions': df['path'].apply(lambda x: os.path.splitext(x)[1]).value_counts().to_dict(),
#             'activity_rate': len(df) / (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
#             if len(df) > 1 else 0
#         }
    
#     def detect_suspicious_activity(self, df: pd.DataFrame) -> List[Dict]:
#         suspicious_patterns = []
        
#         # Check for rapid file modifications
#         time_window = pd.Timedelta(minutes=1)
#         event_counts = df.set_index('timestamp').rolling(time_window).count()
        
#         if (event_counts['event_type'] > 50).any():  # More than 50 events per minute
#             suspicious_patterns.append({
#                 'type': 'high_activity',
#                 'description': 'Unusually high file system activity detected',
#                 'severity': 'high'
#             })
        
#         # Check for suspicious file extensions
#         suspicious_extensions = ['.encrypted', '.locked', '.crypto']
#         suspicious_files = df[df['path'].apply(lambda x: any(ext in x.lower() for ext in suspicious_extensions))]
        
#         if not suspicious_files.empty:
#             suspicious_patterns.append({
#                 'type': 'suspicious_extensions',
#                 'description': 'Files with known ransomware extensions detected',
#                 'severity': 'critical'
#             })
            
#         return suspicious_patterns

# # trainer.py
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.model_selection import train_test_split
# from sklearn.preprocessing import LabelEncoder
# import joblib

# class RansomwareDetectionModel:
#     def __init__(self, model_path: str = 'ransomware_model.joblib'):
#         self.model_path = model_path
#         self.model = None
#         self.label_encoder = LabelEncoder()
    
#     def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
#         # Calculate features from the event data
#         features = pd.DataFrame()
        
#         # Activity-based features
#         features['event_rate'] = df.groupby(df['timestamp'].dt.hour)['event_type'].count()
#         features['modified_ratio'] = (df['event_type'] == 'modified').mean()
#         features['created_ratio'] = (df['event_type'] == 'created').mean()
        
#         # File extension features
#         extensions = df['path'].apply(lambda x: os.path.splitext(x)[1])
#         for ext in extensions.value_counts().head(10).index:
#             features[f'ext_{ext}'] = (extensions == ext).mean()
            
#         return features
    
#     def train(self, df: pd.DataFrame, labels: List[str]):
#         features = self.extract_features(df)
#         encoded_labels = self.label_encoder.fit_transform(labels)
        
#         X_train, X_test, y_train, y_test = train_test_split(
#             features, encoded_labels, test_size=0.2, random_state=42
#         )
        
#         self.model = RandomForestClassifier(n_estimators=100, random_state=42)
#         self.model.fit(X_train, y_train)
        
#         # Save the trained model
#         joblib.dump((self.model, self.label_encoder), self.model_path)
        
#         return self.model.score(X_test, y_test)
    
#     def predict(self, df: pd.DataFrame) -> str:
#         if self.model is None:
#             self.model, self.label_encoder = joblib.load(self.model_path)
            
#         features = self.extract_features(df)
#         prediction = self.model.predict(features)
#         return self.label_encoder.inverse_transform(prediction)[0]

# # Example usage
# def setup_monitoring(watch_directory: str, log_file: str = 'activity_log.json'):
#     # Set up the event handler and observer
#     event_handler = FileEventHandler(log_file)
#     observer = Observer()
#     observer.schedule(event_handler, watch_directory, recursive=True)
#     observer.start()
    
#     # Initialize analyzer and model
#     analyzer = RansomwareAnalyzer(log_file)
#     model = RansomwareDetectionModel()
    
#     return event_handler, observer, analyzer, model


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