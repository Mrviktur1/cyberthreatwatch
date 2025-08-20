import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import random

class GeoMapVisualization:
    def __init__(self):
        self.alerts_data = st.session_state.get('alerts_data', [])
    
    def generate_geo_data(self):
        """Generate geographical data for mapping"""
        if not self.alerts_data:
            return pd.DataFrame()
        
        # Sample country data (in real app, this would come from IP geolocation)
        countries = ['US', 'CN', 'RU', 'DE', 'FR', 'GB', 'JP', 'KR', 'IN', 'BR']
        
        geo_data = []
        for alert in self.alerts_data:
            if alert.get('source_ip'):
                country = random.choice(countries)  # Replace with actual geolocation
                geo_data.append({
                    'country': country,
                    'count': 1,
                    'severity': alert.get('severity', 'Unknown')
                })
        
        if not geo_data:
            return pd.DataFrame()
        
        # Aggregate by country
        df = pd.DataFrame(geo_data)
        aggregated = df.groupby(['country', 'severity']).size().reset_index(name='count')
        
        return aggregated
    
    def render_geo_map(self, df):
        """Render geographical map visualization"""
        if df.empty:
            st.info("No geographical data available for mapping")
            return
        
        # Create choropleth map
        fig = px.choropleth(
            df,
            locations="country",
            locationmode="ISO-3",
            color="count",
            hover_name="country",
            hover_data=["severity", "count"],
            title="Threat Activity by Country",
            color_continuous_scale="reds",
            projection="natural earth"
        )
        
        fig.update_layout(
            height=400,
            margin=dict(l=0, r=0, t=30, b=0)
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    def render_severity_chart(self, df):
        """Render severity distribution chart"""
        if df.empty:
            return
        
        severity_counts = df.groupby('severity')['count'].sum().reset_index()
        
        fig = px.pie(
            severity_counts,
            values='count',
            names='severity',
            title="Alert Severity Distribution",
            hole=0.4
        )
        
        fig.update_traces(textposition='inside', textinfo='percent+label')
        st.plotly_chart(fig, use_container_width=True)
    
    def render(self):
        """Render geo map visualization"""
        st.subheader("🌍 Geographical Analysis")
        
        # Generate and display geo data
        geo_df = self.generate_geo_data()
        
        if not geo_df.empty:
            col1, col2 = st.columns([2, 1])
            
            with col1:
                self.render_geo_map(geo_df)
            
            with col2:
                self.render_severity_chart(geo_df)
        else:
            st.info("No geographical data available. Alerts data needed for mapping.")