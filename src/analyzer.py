import pandas as pd
import numpy as np
from pathlib import Path
import concurrent.futures
import logging
from typing import List, Dict, Tuple
import json
from datetime import datetime

class RansomwareLogProcessor:
    def __init__(self, nat_dir: str, original_dir: str):
        """
        Initialize the log processor with paths to NAT and original scenario directories.
        
        Args:
            nat_dir: Path to directory containing NAT scenario logs
            original_dir: Path to directory containing original scenario logs
        """
        self.nat_dir = Path(nat_dir)
        self.original_dir = Path(original_dir)
        self.setup_logging()
        
    def setup_logging(self):
        """Configure logging for the processor"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def parse_log_line(self, line: str) -> Dict:
        """
        Parse a single log line into structured data.
        """
        try:
            # Split on whitespace since fields are space-separated
            fields = line.strip().split()
            
            # Convert timestamp (which is in seconds) to datetime
            timestamp = float(fields[0])  # This is in seconds
            # Convert to datetime by adding it to a base date
            dt = datetime.fromtimestamp(timestamp)
            
            return {
                'timestamp': dt,
                'src_ip': fields[1],
                'dst_ip': fields[2],
                'src_port': int(fields[3]),
                'dst_port': int(fields[4]),
                'protocol': fields[5],
                'bytes_sent': int(fields[7]) if fields[7] != '-' else 0,
                'bytes_received': int(fields[8]) if fields[8] != '-' else 0
            }
        except Exception as e:
            self.logger.error(f"Error parsing line: {line}")
            self.logger.error(f"Error details: {str(e)}")
            return None

    def extract_features(self, parsed_data: List[Dict]) -> Dict:
        """
        Extract relevant features from parsed log data.
        
        Args:
            parsed_data: List of parsed log line dictionaries
            
        Returns:
            Dictionary of computed features
        """
        if not parsed_data:
            return {}
            
        df = pd.DataFrame(parsed_data)
        
        features = {
            # Time-based features
            'duration_seconds': (df['timestamp'].max() - df['timestamp'].min()).total_seconds(),
            'avg_time_between_packets': df['timestamp'].diff().mean().total_seconds(),
            
            # Network features
            'unique_dst_ips': df['dst_ip'].nunique(),
            'unique_dst_ports': df['dst_port'].nunique(),
            'total_bytes_sent': df['bytes_sent'].sum(),
            'total_bytes_received': df['bytes_received'].sum(),
            'bytes_sent_per_second': df['bytes_sent'].sum() / (df['timestamp'].max() - df['timestamp'].min()).total_seconds(),
            
            # Protocol distribution
            'protocol_distribution': df['protocol'].value_counts().to_dict(),
            
            # Port analysis
            'common_dst_ports': df['dst_port'].value_counts().head(10).to_dict(),
            
            # Traffic patterns
            'avg_packet_size': (df['bytes_sent'] + df['bytes_received']).mean(),
            'packet_size_std': (df['bytes_sent'] + df['bytes_received']).std()
        }
        
        return features

    def process_single_file(self, file_path: Path) -> Tuple[str, Dict]:
        """
        Process a single log file.
        
        Args:
            file_path: Path to log file
            
        Returns:
            Tuple of (ransomware_family, features_dict)
        """
        self.logger.info(f"Processing file: {file_path}")
        
        # Extract ransomware family from path
        ransomware_family = file_path.parent.name
        
        try:
            parsed_data = []
            with open(file_path, 'r') as f:
                for line in f:
                    parsed_line = self.parse_log_line(line)
                    if parsed_line:
                        parsed_data.append(parsed_line)
            
            features = self.extract_features(parsed_data)
            return ransomware_family, features
            
        except Exception as e:
            self.logger.error(f"Error processing file {file_path}: {str(e)}")
            return ransomware_family, {}

    def process_directory(self, directory: Path) -> Dict:
        """
        Process all log files in a directory using parallel execution.
        
        Args:
            directory: Path to directory containing log files
            
        Returns:
            Dictionary mapping ransomware families to their features
        """
        results = {}
        log_files = list(directory.glob('**/*.log'))
        
        with concurrent.futures.ProcessPoolExecutor() as executor:
            future_to_file = {executor.submit(self.process_single_file, file_path): file_path 
                            for file_path in log_files}
            
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    family, features = future.result()
                    if family not in results:
                        results[family] = []
                    results[family].append(features)
                except Exception as e:
                    self.logger.error(f"Error processing {file_path}: {str(e)}")
        
        return results

    def process_all(self) -> Dict:
        """
        Process both NAT and original scenario directories.
        
        Returns:
            Dictionary containing processed data for both scenarios
        """
        self.logger.info("Starting processing of all log files...")
        
        results = {
            'nat_scenario': self.process_directory(self.nat_dir),
            'originalScenario': self.process_directory(self.original_dir)
        }
        
        # Save results to file
        output_file = 'processed_ransomware_data.json'
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        self.logger.info(f"Processing complete. Results saved to {output_file}")
        return results


class RansomwareAnalyzer:
    def __init__(self, log_file: str):
        """Initialize the RansomwareAnalyzer."""
        self.log_file = log_file
        self.setup_logging()
        
    def setup_logging(self):
        """Configure logging for the analyzer"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def load_activity_log(self) -> pd.DataFrame:
        """Load and parse the activity log file into a DataFrame."""
        try:
            with open(self.log_file, 'r') as f:
                data = json.load(f)
            
            if not data:
                return pd.DataFrame()
                
            df = pd.DataFrame(data)
            df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
            return df
            
        except FileNotFoundError:
            self.logger.warning(f"Log file not found: {self.log_file}")
            return pd.DataFrame()
        except Exception as e:
            self.logger.error(f"Error loading activity log: {str(e)}")
            return pd.DataFrame()
    
    def analyze_threats(self, df: pd.DataFrame) -> List[Dict]:
        """Analyze potential threats from the activity log."""
        threats = []
        
        if df.empty:
            return threats
            
        # Group events by path to analyze per-file behavior
        for path, group in df.groupby('path'):
            threat_score = 0
            threat_indicators = []
            
            # Check for rapid file operations
            time_diffs = group['timestamp'].diff()
            if (time_diffs < pd.Timedelta(seconds=1)).any():
                threat_score += 2
                threat_indicators.append("Rapid file operations detected")
            
            # Check for suspicious extensions
            suspicious_extensions = ['.encrypt', '.locked', '.crypted', '.cry', '.crypto']
            if any(ext in str(path).lower() for ext in suspicious_extensions):
                threat_score += 3
                threat_indicators.append("Suspicious file extension detected")
            
            # Check for multiple file modifications
            if len(group) > 10:
                threat_score += 1
                threat_indicators.append("High volume of file operations")
            
            # Add to threats if score exceeds threshold
            if threat_score >= 2:
                threats.append({
                    'path': path,
                    'threat_score': threat_score,
                    'indicators': threat_indicators,
                    'first_seen': group['timestamp'].min(),
                    'last_seen': group['timestamp'].max(),
                    'event_count': len(group)
                })
        
        return sorted(threats, key=lambda x: x['threat_score'], reverse=True)
    
    def get_event_distribution(self, df: pd.DataFrame) -> Dict:
        """Get distribution of event types."""
        if df.empty:
            return {}
            
        return df['event_type'].value_counts().to_dict()
    
    def get_extension_analysis(self, df: pd.DataFrame) -> Dict:
        """Analyze file extensions from the activity log."""
        if df.empty:
            return {}
            
        def get_extension(path):
            return path.split('.')[-1] if '.' in path else 'no_extension'
            
        extensions = df['path'].apply(get_extension)
        return extensions.value_counts().head(10).to_dict()
    
    def get_activity_timeline(self, df: pd.DataFrame, 
                            interval: str = '1min') -> pd.Series:
        """Generate activity timeline with event counts."""
        if df.empty:
            return pd.Series()
            
        return df.set_index('timestamp').resample(interval).size()