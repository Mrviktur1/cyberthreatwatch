import streamlit as st
import pandas as pd
from datetime import datetime, timedelta

class DashboardCards:
    def __init__(self):
        self.metrics = self.calculate_metrics()
    
    def calculate_metrics(self):
        """Calculate dashboard metrics from session state data"""
        alerts_data = st.session_state.get('alerts_data', [])
        threat_data = st.session_state.get('threat_data', [])
        
        # Calculate time-based metrics
        now = datetime.now()
        last_24h_alerts = [alert for alert in alerts_data 
                          if alert.get('timestamp') and 
                          (now - alert['timestamp']).total_seconds() <= 86400]
        
        high_severity_alerts = [alert for alert in alerts_data 
                               if alert.get('severity') == 'High']
        
        return {
            'total_alerts': len(alerts_data),
            'alerts_24h': len(last_24h_alerts),
            'high_severity': len(high_severity_alerts),
            'active_threats': len(threat_data),
            'threat_score_avg': sum(t.get('threat_score', 0) for t in threat_data) / max(len(threat_data), 1)
        }
    
    def render_metric_card(self, title, value, delta=None, delta_color="normal"):
        """Render a single metric card"""
        st.metric(
            label=title,
            value=value,
            delta=delta,
            delta_color=delta_color
        )
    
    def render(self):
        """Render all dashboard cards"""
        st.subheader("📈 Key Metrics")
        
        # Create columns for metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            self.render_metric_card(
                "Total Alerts", 
                self.metrics['total_alerts'],
                f"{self.metrics['alerts_24h']} in 24h"
            )
        
        with col2:
            self.render_metric_card(
                "High Severity", 
                self.metrics['high_severity'],
                delta_color="inverse"
            )
        
        with col3:
            self.render_metric_card(
                "Active Threats", 
                self.metrics['active_threats']
            )
        
        with col4:
            avg_score = round(self.metrics['threat_score_avg'], 1)
            self.render_metric_card(
                "Avg Threat Score", 
                f"{avg_score}/100",
                delta_color="inverse" if avg_score > 50 else "normal"
            )
        
        # Add some spacing
        st.markdown("---")