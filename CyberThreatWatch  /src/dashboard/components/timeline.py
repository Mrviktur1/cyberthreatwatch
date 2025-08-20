import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta

class TimelineVisualization:
    def __init__(self):
        self.alerts_data = st.session_state.get('alerts_data', [])
    
    def process_timeline_data(self):
        """Process data for timeline visualization"""
        if not self.alerts_data:
            return pd.DataFrame()
        
        # Convert to DataFrame
        df = pd.DataFrame(self.alerts_data)
        
        # Ensure timestamp is datetime
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            # Group by time intervals
            df['time_bucket'] = df['timestamp'].dt.floor('H')  # Group by hour
            
            timeline_data = df.groupby(['time_bucket', 'severity']).size().reset_index(name='count')
            return timeline_data
        
        return pd.DataFrame()
    
    def render_timeline_chart(self, df):
        """Render timeline chart"""
        if df.empty:
            st.info("No timeline data available")
            return
        
        fig = px.line(
            df,
            x='time_bucket',
            y='count',
            color='severity',
            title="Alert Timeline",
            labels={'time_bucket': 'Time', 'count': 'Number of Alerts', 'severity': 'Severity'},
            color_discrete_map={
                'High': 'red',
                'Medium': 'orange',
                'Low': 'green',
                'Unknown': 'gray'
            }
        )
        
        fig.update_layout(
            height=300,
            xaxis_title="Time",
            yaxis_title="Number of Alerts",
            hovermode='x unified'
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    def render_alert_frequency(self, df):
        """Render alert frequency statistics"""
        if df.empty:
            return
        
        st.subheader("📊 Alert Frequency")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            total_alerts = df['count'].sum()
            st.metric("Total Alerts", total_alerts)
        
        with col2:
            avg_per_hour = df['count'].mean()
            st.metric("Avg per Hour", f"{avg_per_hour:.1f}")
        
        with col3:
            peak_hour = df.loc[df['count'].idxmax()] if not df.empty else {}
            peak_count = peak_hour.get('count', 0)
            st.metric("Peak Hour", peak_count)
    
    def render(self):
        """Render timeline visualization"""
        st.subheader("⏰ Alert Timeline")
        
        # Process and display timeline data
        timeline_df = self.process_timeline_data()
        
        if not timeline_df.empty:
            self.render_alert_frequency(timeline_df)
            self.render_timeline_chart(timeline_df)
            
            # Show raw data option
            with st.expander("View Raw Timeline Data"):
                st.dataframe(timeline_df, use_container_width=True)
        else:
            st.info("No timeline data available. Alerts with timestamps needed for visualization.")