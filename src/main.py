# main.py
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import time
import os
from pathlib import Path
from monitor import setup_monitoring
import logging
import sqlite3

class RansomwareMonitor:
    def __init__(self):
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('RansomwareMonitor')
        
        # Base paths
        self.base_dir = Path(os.getcwd()) / "data"
        self.nat_directory = self.base_dir / "NATscenario"
        self.original_directory = self.base_dir / "originalScenario"
        self.db_file = Path("src/activity.db")
        
        # Create directories
        self.nat_directory.mkdir(parents=True, exist_ok=True)
        self.original_directory.mkdir(parents=True, exist_ok=True)
        self.db_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize session state
        if 'data_processed' not in st.session_state:
            st.session_state.data_processed = False
        
        if 'monitor_active' not in st.session_state:
            st.session_state.monitor_active = False
            
        # Set up detector only once
        if 'detector' not in st.session_state:
            _, st.session_state.detector = setup_monitoring(
                str(self.base_dir), 
                str(self.db_file)
            )
    
    def process_data(self):
        """Process log files only if not already processed"""
        if not st.session_state.data_processed:
            with st.spinner("Processing log files... This may take a moment."):
                try:
                    for family_dir in self.nat_directory.iterdir():
                        if family_dir.is_dir():
                            for log_type in ["TCPconnInfo.txt", "IOops.txt", "DNSinfo.txt"]:
                                log_file = family_dir / log_type
                                if log_file.exists():
                                    st.session_state.detector.process_log_file(str(log_file))
                    st.session_state.data_processed = True
                    st.success("Data processing complete!")
                except Exception as e:
                    st.error(f"Error processing files: {e}")

    @staticmethod
    @st.cache_data(ttl=5)
    def load_data(limit, current_time):
        """Load and cache data from the database"""
        return st.session_state.detector.get_events(limit=limit)

    def display_metrics(self, df):
        """Display key metrics"""
        if df.empty:
            return

        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Events", len(df))
        with col2:
            unique_ips = pd.concat([
                df['src_ip'].dropna(),
                df['dst_ip'].dropna()
            ]).nunique()
            st.metric("Unique IPs", unique_ips)
        with col3:
            timespan = df['timestamp'].max() - df['timestamp'].min()
            st.metric("Time Span (s)", f"{timespan:.2f}")
        with col4:
            events_per_sec = len(df) / timespan if timespan > 0 else 0
            st.metric("Events/Second", f"{events_per_sec:.2f}")

    def display_timeline(self, df):
        """Display event timeline"""
        if df.empty:
            return

        st.subheader("Activity Timeline")
        df['time'] = pd.to_datetime(df['timestamp'], unit='s')
        timeline = df.groupby([pd.Grouper(key='time', freq='1Min'), 'event_type']).size().reset_index(name='count')
        
        fig = px.line(timeline, x='time', y='count', color='event_type', 
                     title="Event Frequency Over Time")
        st.plotly_chart(fig, use_container_width=True)

    def display_network_analysis(self, df):
        """Display network analysis"""
        if df.empty:
            return

        st.subheader("Network Activity")
        
        # Event type distribution
        event_dist = df['event_type'].value_counts()
        fig = px.pie(values=event_dist.values, names=event_dist.index, 
                    title="Event Type Distribution")
        st.plotly_chart(fig, use_container_width=True)

        # IP analysis
        network_df = df[df['event_type'] == 'network']
        if not network_df.empty:
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("Top Source IPs")
                src_ip_counts = network_df['src_ip'].value_counts().head(10)
                fig = px.bar(x=src_ip_counts.index, y=src_ip_counts.values,
                           title="Top Source IPs")
                st.plotly_chart(fig, use_container_width=True)
                
            with col2:
                st.subheader("Top Destination IPs")
                dst_ip_counts = network_df['dst_ip'].value_counts().head(10)
                fig = px.bar(x=dst_ip_counts.index, y=dst_ip_counts.values,
                           title="Top Destination IPs")
                st.plotly_chart(fig, use_container_width=True)

    def display_filesystem_activity(self, df):
        """Display filesystem activity analysis"""
        filesystem_df = df[df['event_type'] == 'filesystem']
        if filesystem_df.empty:
            return

        st.subheader("Filesystem Activity")
        
        # Operation types
        if 'operation' in filesystem_df.columns:
            op_counts = filesystem_df['operation'].value_counts()
            fig = px.pie(values=op_counts.values, names=op_counts.index,
                        title="Operation Types")
            st.plotly_chart(fig, use_container_width=True)

    def display_threat_analysis(self, df):
        """Display threat analysis"""
        if df.empty:
            return

        st.subheader("Threat Analysis")
        
        # Get recent suspicious events
        recent_time = time.time() - 3600  # Last hour
        suspicious = df[df['timestamp'] > recent_time]
        
        if not suspicious.empty:
            with st.expander("Recent Suspicious Activities", expanded=True):
                for _, event in suspicious.iterrows():
                    event_type = event.get('event_type', 'unknown')
                    if event_type == 'network':
                        st.warning(f"Network connection: {event['src_ip']} → {event['dst_ip']}")
                    elif event_type == 'filesystem':
                        st.warning(f"File operation: {event['operation']} on {event['path']}")

    def run(self):
        st.title("🛡️ Ransomware Detection Monitor")
        
        # Sidebar controls
        st.sidebar.title("Data Source")
        st.sidebar.text(f"Data Directory: {self.base_dir}")
        
        # Process Data button
        if not st.session_state.data_processed:
            if st.sidebar.button("Process Data"):
                self.process_data()
        
        # Monitoring controls
        st.sidebar.title("Monitoring")
        if st.sidebar.checkbox("Enable Live Monitoring", value=st.session_state.monitor_active):
            st.session_state.monitor_active = True
            refresh_rate = st.sidebar.slider("Refresh rate (seconds)", 1, 30, 5)
            auto_refresh = True
        else:
            st.session_state.monitor_active = False
            auto_refresh = False
            refresh_rate = 5
        
        events_to_show = st.sidebar.slider("Events to display", 100, 1000, 500)
        
        # Load data
        df = RansomwareMonitor.load_data(events_to_show, int(time.time()))
        
        if not df.empty:
            # Display components
            self.display_metrics(df)
            self.display_timeline(df)
            
            col1, col2 = st.columns(2)
            with col1:
                self.display_network_analysis(df)
            with col2:
                self.display_filesystem_activity(df)
            
            self.display_threat_analysis(df)
            
            # Recent events table
            st.subheader("Recent Events")
            display_df = df.sort_values('timestamp', ascending=False).head(50)
            if 'id' in display_df.columns:
                display_df = display_df.drop('id', axis=1)
            st.dataframe(display_df, use_container_width=True)
        else:
            if not st.session_state.data_processed:
                st.info("Click 'Process Data' in the sidebar to load the log files.")
            else:
                st.warning("No events found in the database.")
        
        # Auto-refresh only if monitoring is active
        if auto_refresh and st.session_state.monitor_active:
            time.sleep(refresh_rate)
            st.rerun()

def main():
    st.set_page_config(
        page_title="Ransomware Detection Monitor",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    monitor = RansomwareMonitor()
    monitor.run()

if __name__ == "__main__":
    main()