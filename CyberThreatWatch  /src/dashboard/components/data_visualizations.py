import dash_bootstrap_components as dbc
from dash import html, dcc
import plotly.express as px
import pandas as pd
from datetime import datetime, timedelta
import random

class DataVisualizations:
    def __init__(self):
        pass
    
    def create_event_timeline(self):
        # Generate sample data
        dates = [datetime.now() - timedelta(hours=x) for x in range(24)]
        values = [random.randint(10, 100) for _ in range(24)]
        
        df = pd.DataFrame({
            "timestamp": dates,
            "events": values
        })
        
        fig = px.line(df, x="timestamp", y="events", title="Events Over Time")
        fig.update_layout(
            xaxis_title="Time",
            yaxis_title="Number of Events",
            hovermode="x unified"
        )
        
        return dcc.Graph(figure=fig, id="event-timeline")
    
    def create_severity_chart(self):
        severities = ["High", "Medium", "Low", "Info"]
        counts = [12, 45, 78, 156]
        
        fig = px.pie(
            values=counts, 
            names=severities, 
            title="Events by Severity Level",
            color=severities,
            color_discrete_map={"High":"red", "Medium":"orange", "Low":"yellow", "Info":"blue"}
        )
        
        return dcc.Graph(figure=fig, id="severity-chart")
    
    def create_source_chart(self):
        sources = ["Firewall", "IDS", "Server", "Workstation", "Network Device"]
        counts = [45, 32, 67, 89, 23]
        
        fig = px.bar(
            x=sources, 
            y=counts, 
            title="Events by Source Type",
            labels={"x": "Source Type", "y": "Count"}
        )
        
        return dcc.Graph(figure=fig, id="source-chart")
    
    def layout(self):
        return dbc.Row(
            [
                dbc.Col(self.create_event_timeline(), width=8),
                dbc.Col(
                    [
                        self.create_severity_chart(),
                        self.create_source_chart()
                    ],
                    width=4
                )
            ]
        )