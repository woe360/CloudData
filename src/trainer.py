# trainer.py
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import joblib
from typing import Dict, List, Union
import logging
from pathlib import Path

class RansomwareTrainer:
    def __init__(self, model_path: str = 'ransomware_model.joblib'):
        self.model_path = model_path
        self.model = None
        self.label_encoder = LabelEncoder()
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def extract_features_from_logs(self, parsed_data: Dict) -> pd.DataFrame:
        """Extract features from parsed log data (NAT/original scenarios)"""
        features_list = []
        labels = []
        
        # Process each scenario
        for scenario, families in parsed_data.items():
            for family, samples in families.items():
                for sample in samples:
                    if not sample:  # Skip empty samples
                        continue
                    
                    features = {
                        'duration': sample.get('duration_seconds', 0),
                        'avg_packet_interval': sample.get('avg_time_between_packets', 0),
                        'unique_dst_ips': sample.get('unique_dst_ips', 0),
                        'unique_dst_ports': sample.get('unique_dst_ports', 0),
                        'bytes_sent_per_second': sample.get('bytes_sent_per_second', 0),
                        'avg_packet_size': sample.get('avg_packet_size', 0),
                        'packet_size_std': sample.get('packet_size_std', 0),
                    }
                    
                    features_list.append(features)
                    labels.append(f"{scenario}_{family}")
        
        return pd.DataFrame(features_list), labels

    def extract_features_from_events(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract features from real-time event data"""
        if df.empty:
            return pd.DataFrame()
        
        # Group events by time windows (e.g., 1-minute windows)
        df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
        windows = df.groupby(pd.Grouper(key='timestamp', freq='1Min'))
        
        features_list = []
        for _, window in windows:
            if window.empty:
                continue
                
            features = {
                'event_rate': len(window),
                'modified_ratio': (window['event_type'] == 'modified').mean(),
                'created_ratio': (window['event_type'] == 'created').mean(),
                'unique_extensions': window['path'].apply(lambda x: Path(x).suffix).nunique(),
                'suspicious_extensions': window['path'].apply(
                    lambda x: Path(x).suffix.lower() in ['.encrypted', '.locked', '.crypto']
                ).any(),
            }
            features_list.append(features)
        
        return pd.DataFrame(features_list)

    def train_on_logs(self, parsed_data: Dict) -> float:
        """Train model on historical log data"""
        features_df, labels = self.extract_features_from_logs(parsed_data)
        if features_df.empty:
            raise ValueError("No valid features extracted from log data")
        
        return self._train_model(features_df, labels)
    
    def train_on_events(self, events_df: pd.DataFrame, labels: List[str]) -> float:
        """Train model on real-time event data"""
        features_df = self.extract_features_from_events(events_df)
        if features_df.empty:
            raise ValueError("No valid features extracted from event data")
        
        return self._train_model(features_df, labels)
    
    def _train_model(self, features: pd.DataFrame, labels: List[str]) -> float:
        """Internal method to train the model"""
        encoded_labels = self.label_encoder.fit_transform(labels)
        
        X_train, X_test, y_train, y_test = train_test_split(
            features, encoded_labels, test_size=0.2, random_state=42
        )
        
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
        self.model.fit(X_train, y_train)
        accuracy = self.model.score(X_test, y_test)
        
        # Save the trained model
        joblib.dump((self.model, self.label_encoder), self.model_path)
        self.logger.info(f"Model trained with accuracy: {accuracy:.2f}")
        
        return accuracy
    
    def predict(self, data: Union[Dict, pd.DataFrame]) -> str:
        """Predict on either log data or event data"""
        if self.model is None:
            self.model, self.label_encoder = joblib.load(self.model_path)
        
        # Handle different input types
        if isinstance(data, dict):
            features_df, _ = self.extract_features_from_logs({'predict': {'sample': [data]}})
        else:
            features_df = self.extract_features_from_events(data)
        
        if features_df.empty:
            raise ValueError("Could not extract features from input data")
        
        prediction = self.model.predict(features_df)
        return self.label_encoder.inverse_transform(prediction)[0]

# Example usage
if __name__ == "__main__":
    trainer = RansomwareTrainer()
    
    # Example: Train on log data
    from data_processor import RansomwareLogProcessor
    
    processor = RansomwareLogProcessor("data/NATscenario", "data/originalScenario")
    parsed_data = processor.process_all()
    accuracy = trainer.train_on_logs(parsed_data)
    print(f"Model trained on log data with accuracy: {accuracy:.2f}")