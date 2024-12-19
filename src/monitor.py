# import os
# import time
# import json
# from watchdog.observers import Observer
# from watchdog.events import FileSystemEventHandler
# from collections import defaultdict
# import logging
# import pandas as pd
# from ml_training import RansomwareML

# class RansomwareDetector:
#     def __init__(self, watch_directory):
#         self.watch_directory = watch_directory
#         self.alert_threshold = 10
#         self.suspicious_extensions = {'.encrypted', '.crypto', '.locked', '.decrypt'}
#         self.activity_log = defaultdict(list)
        
#         # Initialize ML detector
#         self.ml_detector = RansomwareML()
#         try:
#             self.ml_detector.load_model('ransomware_model.joblib')
#             self.using_ml = True
#             print("ML model loaded successfully")
#         except Exception as e:
#             self.using_ml = False
#             print(f"Could not load ML model: {e}. Using only rule-based detection.")
        
#         logging.basicConfig(level=logging.INFO)
#         self.logger = logging.getLogger('RansomwareDetector')
    
#     def check_suspicious_activity(self, event_time, event_type, file_path):
#         one_minute_ago = event_time - 60
#         recent_events = [event for event in self.activity_log['events'] 
#                         if event['timestamp'] > one_minute_ago]
        
#         # Traditional rule-based detection
#         _, ext = os.path.splitext(file_path)
#         is_suspicious_ext = ext.lower() in self.suspicious_extensions
#         high_activity = len(recent_events) > self.alert_threshold
        
#         # ML-based detection
#         ml_suspicious = False
#         if self.using_ml and recent_events:
#             try:
#                 recent_df = pd.DataFrame(recent_events)
#                 ml_suspicious = self.ml_detector.predict(recent_df)
#             except Exception as e:
#                 self.logger.error(f"ML prediction error: {e}")
        
#         # Combined detection
#         if is_suspicious_ext or high_activity or ml_suspicious:
#             self.logger.warning("ALERT: Suspicious activity detected!")
#             self.logger.warning(f"File: {file_path}")
            
#             # Collect all triggered detection methods
#             reasons = []
#             if is_suspicious_ext:
#                 reasons.append("Suspicious extension detected")
#             if high_activity:
#                 reasons.append("High modification rate")
#             if ml_suspicious:
#                 reasons.append("ML model detected suspicious pattern")
                
#             self.logger.warning("Reasons: " + ", ".join(reasons))
            
#             # Save alert to file
#             self.save_alert(event_time, file_path, reasons)
#             return True
#         return False
    
#     def save_alert(self, event_time, file_path, reasons):
#         """Save alert details to a file for later analysis"""
#         alert = {
#             'timestamp': event_time,
#             'file_path': file_path,
#             'reasons': reasons,
#             'recent_events_count': len(self.activity_log['events'])
#         }
        
#         try:
#             alerts = []
#             if os.path.exists('alerts.json'):
#                 with open('alerts.json', 'r') as f:
#                     alerts = json.load(f)
            
#             alerts.append(alert)
            
#             with open('alerts.json', 'w') as f:
#                 json.dump(alerts, f, indent=2)
#         except Exception as e:
#             self.logger.error(f"Error saving alert: {e}")

# class FileMonitor(FileSystemEventHandler):
#     def __init__(self, detector):
#         self.detector = detector

#     def on_modified(self, event):
#         if not event.is_directory:
#             current_time = time.time()
#             self.detector.activity_log['events'].append({
#                 'timestamp': current_time,
#                 'event_type': 'modified',
#                 'path': event.src_path
#             })
#             self.detector.check_suspicious_activity(current_time, 'modified', 
#                                                  event.src_path)

#     def on_created(self, event):
#         if not event.is_directory:
#             current_time = time.time()
#             self.detector.activity_log['events'].append({
#                 'timestamp': current_time,
#                 'event_type': 'created',
#                 'path': event.src_path
#             })
#             self.detector.check_suspicious_activity(current_time, 'created', 
#                                                  event.src_path)

# def main():
#     watch_directory = "."
#     detector = RansomwareDetector(watch_directory)
#     detector.activity_log['events'] = []
    
#     event_handler = FileMonitor(detector)
#     observer = Observer()
#     observer.schedule(event_handler, watch_directory, recursive=True)
#     observer.start()
    
#     print(f"Monitoring directory: {os.path.abspath(watch_directory)}")
#     print("Press Ctrl+C to stop monitoring")
    
#     try:
#         while True:
#             time.sleep(1)
#     except KeyboardInterrupt:
#         observer.stop()
#         print("\nStopping monitor...")
#     observer.join()

# if __name__ == "__main__":
#     main()


import os
import time
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import defaultdict
import logging
import pandas as pd
from ml_training import RansomwareML

class RansomwareDetector:
    def __init__(self, watch_directory):
        self.watch_directory = watch_directory
        self.alert_threshold = 10
        self.suspicious_extensions = {'.encrypted', '.crypto', '.locked', '.decrypt'}
        self.activity_log = {'events': []}  # Changed to list with events key
        
        # Initialize ML detector
        self.ml_detector = RansomwareML()
        try:
            self.ml_detector.load_model('ransomware_model.joblib')
            self.using_ml = True
            print("ML model loaded successfully")
        except Exception as e:
            self.using_ml = False
            print(f"Could not load ML model: {e}. Using only rule-based detection.")
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger('RansomwareDetector')
    
    def save_activity_log(self):
        """Save activity log to file"""
        try:
            with open('activity_log.json', 'w') as f:
                json.dump(self.activity_log, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving activity log: {e}")
    
    def check_suspicious_activity(self, event_time, event_type, file_path):
        one_minute_ago = event_time - 60
        recent_events = [event for event in self.activity_log['events'] 
                        if event['timestamp'] > one_minute_ago]
        
        # Traditional rule-based detection
        _, ext = os.path.splitext(file_path)
        is_suspicious_ext = ext.lower() in self.suspicious_extensions
        high_activity = len(recent_events) > self.alert_threshold
        
        # ML-based detection
        ml_suspicious = False
        if self.using_ml and recent_events:
            try:
                recent_df = pd.DataFrame(recent_events)
                ml_suspicious = self.ml_detector.predict(recent_df)
            except Exception as e:
                self.logger.error(f"ML prediction error: {e}")
        
        # Save activity log after each check
        self.save_activity_log()
        
        if is_suspicious_ext or high_activity or ml_suspicious:
            self.logger.warning("ALERT: Suspicious activity detected!")
            self.logger.warning(f"File: {file_path}")
            reasons = []
            if is_suspicious_ext:
                reasons.append("Suspicious extension detected")
            if high_activity:
                reasons.append("High modification rate")
            if ml_suspicious:
                reasons.append("ML model detected suspicious pattern")
            
            self.logger.warning("Reasons: " + ", ".join(reasons))
            self.save_alert(event_time, file_path, reasons)
            return True
        return False

class FileMonitor(FileSystemEventHandler):
    def __init__(self, detector):
        self.detector = detector

    def on_modified(self, event):
        if not event.is_directory:
            current_time = time.time()
            self.detector.activity_log['events'].append({
                'timestamp': current_time,
                'event_type': 'modified',
                'path': event.src_path
            })
            self.detector.save_activity_log()  # Save after each event
            self.detector.check_suspicious_activity(current_time, 'modified', event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            current_time = time.time()
            self.detector.activity_log['events'].append({
                'timestamp': current_time,
                'event_type': 'created',
                'path': event.src_path
            })
            self.detector.save_activity_log()  # Save after each event
            self.detector.check_suspicious_activity(current_time, 'created', event.src_path)

def main():
    watch_directory = "."
    detector = RansomwareDetector(watch_directory)
    
    event_handler = FileMonitor(detector)
    observer = Observer()
    observer.schedule(event_handler, watch_directory, recursive=True)
    observer.start()
    
    print(f"Monitoring directory: {os.path.abspath(watch_directory)}")
    print("Press Ctrl+C to stop monitoring")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\nStopping monitor...")
    observer.join()

if __name__ == "__main__":
    main()