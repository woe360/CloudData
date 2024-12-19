import streamlit as st
import pandas as pd
import plotly.express as px
import json
from datetime import datetime, timedelta
import time
import os

def load_activity_log():
    try:
        with open('activity_log.json', 'r') as f:
            data = json.load(f)
            if 'events' in data:
                return pd.DataFrame(data['events'])
    except Exception as e:
        st.error('Error loading activity log')
    return pd.DataFrame()

def main():
    st.title("Ransomware Detection Monitor")
    
    # Load and process data
    df = load_activity_log()
    
    if not df.empty:
        # Convert timestamps
        df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
        
        # Basic metrics
        total_events = len(df)
        st.metric("Total Events", total_events)
        
        # Timeline
        st.subheader("Activity Timeline")
        fig = px.histogram(df, x='timestamp', title='File Events Over Time')
        st.plotly_chart(fig)
        
        # Recent events
        st.subheader("Recent Events")
        recent_df = df.tail(10)
        st.dataframe(recent_df)
    else:
        st.info("No data available")
    
    # Auto-refresh
    if st.sidebar.checkbox('Auto-refresh'):
        time.sleep(5)
        st.experimental_rerun()

if __name__ == "__main__":
    main()
