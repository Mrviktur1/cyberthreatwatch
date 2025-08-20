import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime, timedelta

class VisualizationTools:
    def __init__(self):
        pass
    
    def create_timeline_chart(self, data, time_field='timestamp', value_field='count'):
        """Create a timeline chart from data"""
        if not data:
            return self._create_empty_chart("No data available")
        
        df = pd.DataFrame(data)
        df[time_field] = pd.to_datetime(df[time_field])
        
        fig = px.line(df, x=time_field, y=value_field, title="Events Timeline")
        fig.update_layout(
            xaxis_title="Time",
            yaxis_title="Number of Events",
            hovermode="x unified"
        )
        return fig
    
    def create_pie_chart(self, data, category_field, value_field):
        """Create a pie chart from categorized data"""
        if not data:
            return self._create_empty_chart("No data available")
        
        df = pd.DataFrame(data)
        fig = px.pie(df, names=category_field, values=value_field, title="Distribution")
        return fig
    
    def create_bar_chart(self, data, x_field, y_field, title="Bar Chart"):
        """Create a bar chart from data"""
        if not data:
            return self._create_empty_chart("No data available")
        
        df = pd.DataFrame(data)
        fig = px.bar(df, x=x_field, y=y_field, title=title)
        return fig
    
    def create_heatmap(self, data, x_field, y_field, values_field):
        """Create a heatmap from data"""
        if not data:
            return self._create_empty_chart("No data available")
        
        df = pd.DataFrame(data)
        pivot_df = df.pivot_table(values=values_field, index=y_field, columns=x_field, aggfunc='count', fill_value=0)
        
        fig = px.imshow(pivot_df, title="Event Heatmap")
        return fig
    
    def _create_empty_chart(self, message):
        """Create an empty chart with message"""
        fig = go.Figure()
        fig.add_annotation(
            text=message,
            xref="paper", yref="paper",
            x=0.5, y=0.5,
            showarrow=False,
            font=dict(size=20)
        )
        return fig
    
    def apply_theme(self, fig, theme='light'):
        """Apply theme to chart"""
        if theme == 'dark':
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font_color='white'
            )
        return fig