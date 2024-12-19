import pandas as pd
import numpy as np
from pathlib import Path
import logging
from typing import List, Dict, Tuple, Generator
import json
from datetime import datetime
import psutil
import itertools
from tqdm import tqdm

class RansomwareLogProcessor:
    def __init__(self, nat_dir: str, original_dir: str, chunk_size: int = 1000):
        """
        Initialize the log processor with paths to NAT and original scenario directories.
        
        Args:
            nat_dir (str): Path to NAT scenario directory
            original_dir (str): Path to original scenario directory
            chunk_size (int): Number of lines to process at once
        """
        self.nat_dir = Path(nat_dir)
        self.original_dir = Path(original_dir)
        self.chunk_size = chunk_size
        self.temp_dir = Path('temp_processed_data')
        self.temp_dir.mkdir(exist_ok=True)
        self.setup_logging()
        
    def setup_logging(self):
        """Configure logging for the processor"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
    def check_memory_usage(self):
        """Monitor memory usage and log warning if too high"""
        process = psutil.Process()
        memory_info = process.memory_info()
        memory_gb = memory_info.rss / 1024 / 1024 / 1024  # Convert to GB
        
        if memory_gb > 1.0:  # Warning at 1GB
            self.logger.warning(f"High memory usage detected: {memory_gb:.2f}GB")
            
    def parse_log_line(self, line: str, log_type: str) -> Dict:
        """Parse a single log line based on log type"""
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
                
            if log_type == "DNSinfo.txt":
                if len(fields) < 3:
                    return None
                return {
                    'timestamp': timestamp,
                    'src_ip': fields[1].split(':')[0],
                    'dst_ip': fields[2].split(':')[0],
                    'dns_query': fields[4] if len(fields) > 4 else None,
                    'response': fields[5] if len(fields) > 5 else None
                }
                
            elif log_type == "TCPconnInfo.txt":
                if len(fields) < 3:
                    return None
                try:
                    src_parts = fields[1].split(':')
                    dst_parts = fields[2].split(':')
                    return {
                        'timestamp': timestamp,
                        'src_ip': src_parts[0],
                        'dst_ip': dst_parts[0],
                        'src_port': int(src_parts[1]) if len(src_parts) > 1 else None,
                        'dst_port': int(dst_parts[1]) if len(dst_parts) > 1 else None,
                        'smb_command': fields[3] if len(fields) > 3 else None
                    }
                except (IndexError, ValueError):
                    return None
                    
            elif log_type == "IOops.txt":
                if len(fields) < 2:
                    return None
                return {
                    'timestamp': timestamp,
                    'operation': fields[1] if len(fields) > 1 else None,
                    'file_path': ' '.join(fields[2:]) if len(fields) > 2 else None
                }
                
        except Exception as e:
            self.logger.error(f"Error parsing line: {line}")
            self.logger.error(f"Error details: {str(e)}")
            return None

    def process_file_chunks(self, file_path: Path) -> Generator[Dict, None, None]:
        """Process a file in chunks using a generator"""
        encodings = ['utf-8', 'latin1', 'cp1252']
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    chunk = []
                    for line in f:
                        parsed_line = self.parse_log_line(line, file_path.name)
                        if parsed_line:
                            chunk.append(parsed_line)
                            
                            if len(chunk) >= self.chunk_size:
                                yield chunk
                                chunk = []
                                self.check_memory_usage()
                    
                    if chunk:  # Yield remaining data
                        yield chunk
                break  # If successful, break the encoding loop
                
            except UnicodeDecodeError:
                continue
            except Exception as e:
                self.logger.error(f"Error processing {file_path}: {str(e)}")
                break

    def save_chunk_to_temp(self, chunk: List[Dict], family: str, scenario: str, log_type: str):
        """Save a chunk of processed data to a temporary file"""
        temp_file = self.temp_dir / f"{scenario}_{family}_{log_type}_{datetime.now().timestamp()}.json"
        with open(temp_file, 'w') as f:
            json.dump({
                'scenario': scenario,
                'family': family,
                'log_type': log_type,
                'data': chunk
            }, f)

    def process_directory(self, directory: Path, scenario: str) -> None:
        """Process all log files in a directory"""
        log_types = ["DNSinfo.txt", "IOops.txt", "TCPconnInfo.txt"]
        
        for log_type in log_types:
            log_files = list(directory.glob(f"**/{log_type}"))
            
            for file_path in tqdm(log_files, desc=f"Processing {log_type} files"):
                family = file_path.parent.name
                
                for chunk in self.process_file_chunks(file_path):
                    self.save_chunk_to_temp(chunk, family, scenario, log_type)

    def merge_temp_files(self) -> Dict:
        """Merge all temporary files into final result"""
        results = {
            'nat_scenario': {},
            'original_scenario': {}
        }
        
        for temp_file in self.temp_dir.glob('*.json'):
            with open(temp_file, 'r') as f:
                data = json.load(f)
                scenario = data['scenario']
                family = data['family']
                
                if family not in results[scenario]:
                    results[scenario][family] = []
                    
                results[scenario][family].extend(data['data'])
            
            temp_file.unlink()  # Delete temp file after processing
            
        return results

    def process_all(self) -> Dict:
        """Process both NAT and original scenario directories"""
        self.logger.info("Starting processing of all log files...")
        
        # Process directories
        self.process_directory(self.nat_dir, 'nat_scenario')
        self.process_directory(self.original_dir, 'original_scenario')
        
        # Merge results
        results = self.merge_temp_files()
        
        # Save final results
        output_file = 'processed_ransomware_data.json'
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # Clean up temp directory
        self.temp_dir.rmdir()
        
        self.logger.info(f"Processing complete. Results saved to {output_file}")
        return results

# Usage example
if __name__ == "__main__":
    processor = RansomwareLogProcessor(
        nat_dir="data/NATscenario",
        original_dir="data/originalScenario",
        chunk_size=1000
    )
    results = processor.process_all()