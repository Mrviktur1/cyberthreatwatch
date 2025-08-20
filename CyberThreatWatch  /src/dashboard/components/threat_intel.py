import streamlit as st
import pandas as pd
from datetime import datetime

class ThreatIntelPanel:
    def __init__(self):
        self.threat_data = st.session_state.get('threat_data', [])
    
    def process_threat_data(self):
        """Process threat data for display"""
        if not self.threat_data:
            return pd.DataFrame()
        
        df = pd.DataFrame(self.threat_data)
        
        # Add calculated columns
        if 'first_seen' in df.columns and 'last_seen' in df.columns:
            df['duration_days'] = (pd.to_datetime(df['last_seen']) - 
                                  pd.to_datetime(df['first_seen'])).dt.days
        
        # Sort by threat score
        if 'threat_score' in df.columns:
            df = df.sort_values('threat_score', ascending=False)
        
        return df
    
    def render_threat_table(self, df):
        """Render threat intelligence table"""
        if df.empty:
            st.info("No threat intelligence data available")
            return
        
        # Display key metrics
        st.write(f"**Total Threats:** {len(df)}")
        if 'threat_score' in df.columns:
            st.write(f"**Average Score:** {df['threat_score'].mean():.1f}/100")
        
        # Display table
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "indicator": "Indicator",
                "type": "Type",
                "threat_score": st.column_config.NumberColumn(
                    "Threat Score",
                    format="%d/100",
                    help="Threat score from 0-100"
                ),
                "first_seen": "First Seen",
                "last_seen": "Last Seen",
                "duration_days": st.column_config.NumberColumn(
                    "Duration (days)",
                    format="%d days"
                )
            }
        )
    
    def render(self):
        """Render threat intelligence panel"""
        st.subheader("🛡️ Threat Intelligence")
        
        # Process and display data
        threat_df = self.process_threat_data()
        self.render_threat_table(threat_df)
        
        # Add refresh button
        if st.button("🔄 Refresh Threat Data", key="refresh_threats"):
            st.rerun()