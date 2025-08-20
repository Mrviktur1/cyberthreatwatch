import dash_bootstrap_components as dbc
from dash import html
from ..components.alerts_panel import AlertsPanel

class AlertsPage:
    def __init__(self):
        self.alerts_panel = AlertsPanel()
    
    def layout(self):
        return html.Div(
            [
                html.H1("Security Alerts", className="text-center mb-4"),
                self.alerts_panel.layout(),
                html.Hr(),
                html.H3("Alert Management"),
                dbc.Row(
                    [
                        dbc.Col(
                            dbc.Button("Acknowledge All", color="warning", className="me-2"),
                            width="auto"
                        ),
                        dbc.Col(
                            dbc.Button("Export Alerts", color="info"),
                            width="auto"
                        )
                    ]
                )
            ]
        )