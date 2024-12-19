# dashboard.py
import streamlit as st
import pandas as pd
import plotly.express as px
import json
from datetime import datetime, timedelta
import time
import os
from trainer import RansomwareTrainer

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
    
    # Sidebar controls
    st.sidebar.title("Controls")
    events_to_show = st.sidebar.slider("Number of events to display", 10, 100, 50)
    auto_refresh = st.sidebar.checkbox('Auto-refresh')
    refresh_rate = st.sidebar.slider("Refresh rate (seconds)", 1, 10, 5)
    
    # Load and process data
    df = load_activity_log()
    
    if not df.empty:
        # Convert timestamps
        df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
        
        # Basic metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Events", len(df))
        with col2:
            created_count = len(df[df['event_type'] == 'created'])
            st.metric("Files Created", created_count)
        with col3:
            modified_count = len(df[df['event_type'] == 'modified'])
            st.metric("Files Modified", modified_count)
        
        # Timeline
        st.subheader("Activity Timeline")
        fig = px.histogram(df, 
                         x='timestamp', 
                         title='File Events Over Time',
                         color='event_type',  # Color bars by event type
                         nbins=50)  # Adjust number of bins
        st.plotly_chart(fig)
        
        # Event type distribution
        st.subheader("Event Type Distribution")
        event_counts = df['event_type'].value_counts()
        fig2 = px.pie(values=event_counts.values, 
                     names=event_counts.index, 
                     title='Distribution of Event Types')
        st.plotly_chart(fig2)
        
        # Recent events
        st.subheader(f"Recent Events (Last {events_to_show})")
        recent_df = df.tail(events_to_show)
        st.dataframe(recent_df, use_container_width=True)
        
        # File extension analysis
        st.subheader("File Extension Analysis")
        extensions = recent_df['path'].apply(lambda x: os.path.splitext(x)[1])
        ext_counts = extensions.value_counts()
        fig3 = px.bar(x=ext_counts.index, 
                     y=ext_counts.values,
                     title='File Extensions Distribution',
                     labels={'x': 'Extension', 'y': 'Count'})
        st.plotly_chart(fig3)
    else:
        st.info("No data available")
    
    # Auto-refresh logic
    if auto_refresh:
        time.sleep(refresh_rate)
        st.rerun()

if __name__ == "__main__":
    main()