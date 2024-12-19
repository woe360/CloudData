import streamlit as st
import pandas as pd
import plotly.express as px
import json
from datetime import datetime, timedelta
import time
import os
from watchdog.observers import Observer
from trainer import RansomwareTrainer
from analyzer import RansomwareAnalyzer
from file_monitor import FileEventHandler
from data_processor import RansomwareLogProcessor

class RansomwareMonitor:
    def __init__(self):
        # Base paths
        self.base_dir = os.path.join(os.getcwd(), "data")
        self.nat_directory = os.path.join(self.base_dir, "NATscenario")
        self.original_directory = os.path.join(self.base_dir, "originalScenario")
        self.log_file = os.path.join("src", "activity_log.json")
        
        # Log file types
        self.log_types = ["DNSinfo.txt", "IOops.txt", "TCPconnInfo.txt"]
        
        # Create directories if they don't exist
        os.makedirs(self.nat_directory, exist_ok=True)
        os.makedirs(self.original_directory, exist_ok=True)
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        
        # Get all ransomware families
        self.ransomware_families = [
            d for d in os.listdir(self.nat_directory) 
            if os.path.isdir(os.path.join(self.nat_directory, d))
        ]
        
        # Process historical data first
        self.processor = RansomwareLogProcessor(self.nat_directory, self.original_directory)
        try:
            st.info("Processing historical data...")
            parsed_data = self.processor.process_all()
            
            # Train model with processed data
            self.trainer = RansomwareTrainer()
            self.trainer.train_on_logs(parsed_data)
            print("Initial model training completed!")
        except Exception as e:
            print(f"Error during initial processing: {str(e)}")
        
        # Initialize monitoring components
        self.event_handler = FileEventHandler(self.log_file)
        self.observer = Observer()
        self.analyzer = RansomwareAnalyzer(self.log_file)
        
        # Start real-time monitoring
        self.observer.schedule(self.event_handler, self.nat_directory, recursive=True)
        self.observer.start()

    def train_model(self):
        """Train/update the model"""
        try:
            parsed_data = self.processor.process_all()
            self.trainer.train_on_logs(parsed_data)
            print("Model training completed!")
        except Exception as e:
            print(f"Error training model: {str(e)}")
            time.sleep(1)

    def display_family_selector(self):
        """Add ransomware family selector to sidebar"""
        st.sidebar.subheader("Ransomware Family Selection")
        selected_family = st.sidebar.selectbox(
            "Select Family to Analyze",
            ["All"] + self.ransomware_families
        )
        return selected_family

    def filter_data_by_family(self, df, family):
        """Filter dataframe based on selected family"""
        if family != "All":
            return df[df['path'].str.contains(family, na=False)]
        return df

    def load_activity_log(self):
        """Load activity log data"""
        try:
            return self.analyzer.load_activity_log()
        except Exception as e:
            st.error(f"Error loading activity log: {str(e)}")
            return pd.DataFrame()

    def display_metrics(self, df):
        """Display key metrics"""
        if df.empty:
            return

        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Events", len(df))
        with col2:
            st.metric("Unique Files", df['path'].nunique())
        with col3:
            timespan = (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
            st.metric("Time Span (s)", f"{timespan:.2f}")
        with col4:
            events_per_sec = len(df) / timespan if timespan > 0 else 0
            st.metric("Events/Second", f"{events_per_sec:.2f}")

    def display_timeline(self, df):
        """Display activity timeline"""
        if df.empty:
            return

        st.subheader("Activity Timeline")
        timeline_data = self.analyzer.get_activity_timeline(df)
        if not timeline_data.empty:
            fig = px.line(timeline_data, title="Event Frequency Over Time")
            st.plotly_chart(fig)

    def display_event_distribution(self, df):
        """Display event type distribution"""
        if df.empty:
            return

        st.subheader("Event Distribution")
        distribution = self.analyzer.get_event_distribution(df)
        if distribution:
            fig = px.pie(values=list(distribution.values()),
                        names=list(distribution.keys()),
                        title="Event Types")
            st.plotly_chart(fig)

    def display_extension_analysis(self, df):
        """Display file extension analysis"""
        if df.empty:
            return

        st.subheader("File Extensions")
        extensions = self.analyzer.get_extension_analysis(df)
        if extensions:
            fig = px.bar(x=list(extensions.keys()),
                        y=list(extensions.values()),
                        title="File Extensions")
            st.plotly_chart(fig)

    def display_threat_analysis(self, df):
        """Display threat analysis"""
        if df.empty:
            return

        st.subheader("Threat Analysis")
        threats = self.analyzer.analyze_threats(df)
        
        if threats:
            for threat in threats:
                with st.expander(f"Threat Score: {threat['threat_score']} - {threat['path']}"):
                    st.write(f"First seen: {threat['first_seen']}")
                    st.write(f"Last seen: {threat['last_seen']}")
                    st.write(f"Event count: {threat['event_count']}")
                    st.write("Indicators:")
                    for indicator in threat['indicators']:
                        st.write(f"- {indicator}")

    def display_recent_events(self, df, num_events):
        """Display recent events"""
        if df.empty:
            return

        st.subheader("Recent Events")
        recent = df.sort_values('timestamp', ascending=False).head(num_events)
        st.dataframe(recent)

    def run(self):
        try:
            st.title("🛡️ Ransomware Detection Monitor")
            
            # Display data source information
            st.sidebar.title("Data Source")
            st.sidebar.text(f"NAT Scenario: {self.nat_directory}")
            st.sidebar.text(f"Log Types: {', '.join(self.log_types)}")
            
            # Family selector
            selected_family = self.display_family_selector()
            
            # Sidebar controls
            st.sidebar.title("Controls")
            events_to_show = st.sidebar.slider("Number of events to display", 10, 100, 50)
            auto_refresh = st.sidebar.checkbox('Auto-refresh')
            refresh_rate = st.sidebar.slider("Refresh rate (seconds)", 1, 10, 5)
            
            # Model training controls
            self.train_model()
            
            # Load and process data
            df = self.load_activity_log()
            
            if not df.empty:
                # Apply family filter
                df = self.filter_data_by_family(df, selected_family)
                
                # Convert timestamps
                df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
                
                # Display components
                self.display_metrics(df)
                self.display_timeline(df)
                
                col1, col2 = st.columns(2)
                with col1:
                    self.display_event_distribution(df)
                with col2:
                    self.display_extension_analysis(df)
                
                self.display_threat_analysis(df)
                self.display_recent_events(df, events_to_show)
            else:
                st.info("No data available - Processing initial data...")
            
            # Auto-refresh logic
            if auto_refresh:
                time.sleep(refresh_rate)
                st.rerun()

        except Exception as e:
            st.error(f"An error occurred: {str(e)}")
            st.error(f"Error details: {str(e)}")
        
        finally:
            self.observer.stop()
            self.observer.join()

def main():
    monitor = RansomwareMonitor()
    monitor.run()

if __name__ == "__main__":
    main()