# Ransomware Detection and Analysis System
1. Problem Description
This project addresses the critical challenge of detecting and analyzing ransomware behavior in real-time. Ransomware attacks have become increasingly sophisticated and frequent, requiring advanced detection systems that can process large volumes of system activity data to identify malicious patterns before extensive damage occurs.
2. Need for Big Data and Cloud
The system processes massive amounts of behavioral data from multiple ransomware families, including network connections, DNS queries, and file system operations. Cloud infrastructure is essential because:

Individual log files can reach several GB in size
Real-time processing requires substantial computational resources
Multiple data streams need to be analyzed simultaneously
Machine learning models require significant processing power for training

3. Data Description

Source: IEEE DataPort's Open Repository for Evaluation of Ransomware Detection Tools
Dataset contains behavioral data from multiple ransomware families including CTBLocker, Cryxos, DMALocker, and others
Data types:

TCPconnInfo.txt: Network connection logs
DNSinfo.txt: DNS query records
IOops.txt: File system operations


Format: Structured text files with timestamp-based entries
Size: Multiple GB of log data across different ransomware families
Data collection period: 2016-2018

4. Application Description

Platform: Python-based application with Streamlit dashboard
Programming Models:

Real-time stream processing for log analysis
Batch processing for historical data
Machine learning for pattern detection


Infrastructure: Local/Cloud deployment options with scalable processing capabilities

5. Software Design
Architecture:

RansomwareLogProcessor: Core data processing engine
RansomwareAnalyzer: Analysis and detection component
RansomwareTrainer: ML model training module
Streamlit Dashboard: Real-time visualization

Dependencies:

pandas: Data processing
streamlit: Dashboard interface
scikit-learn: Machine learning
psutil: System resource monitoring
tqdm: Progress tracking
plotly: Data visualization

6. Usage
Basic setup and running:
bashCopy# Install dependencies
pip install -r requirements.txt

# Run the dashboard
streamlit run src/main.py

# Process specific log files
python src/data_processor.py --nat-dir data/NATscenario --original-dir data/originalScenario
7. Performance Evaluation

Processing speed varies by log type:

DNSinfo.txt: ~150 files/second
TCPconnInfo.txt: ~100 files/second
IOops.txt: ~0.12 files/second (most resource-intensive)


Memory optimization through chunk processing
Scalable based on available system resources

8. Advanced Features

Real-time memory monitoring and optimization
Multi-encoding support for log files
Incremental processing with temporary storage
Adaptive chunk sizing based on system resources
ML-based pattern detection for unknown ransomware variants

9. Conclusions
Achievements:

Successfully processes large volumes of ransomware behavioral data
Real-time monitoring and visualization capabilities
Memory-efficient processing of large log files

Future Work:

Implementation of distributed processing
Enhanced ML model training
Integration with cloud-based storage
Addition of more ransomware families
Improved visualization and reporting

10. References

IEEE DataPort. "Open Repository for Evaluation of Ransomware Detection Tools." https://ieee-dataport.org/open-access/open-repository-evaluation-ransomware-detection-tools
Streamlit Documentation. https://docs.streamlit.io/
scikit-learn Documentation. https://scikit-learn.org/
Python psutil Documentation. https://psutil.readthedocs.io/
