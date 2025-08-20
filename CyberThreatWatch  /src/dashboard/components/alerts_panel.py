import dash_bootstrap_components as dbc
from dash import html, dcc
import pandas as pd
from datetime import datetime, timedelta

class AlertsPanel:
    def __init__(self):
        pass
    
    def layout(self):
        # Sample alert data
        alerts_data = [
            {"id": 1, "severity": "High", "message": "Multiple failed login attempts", "timestamp": "2023-08-19 10:30:45", "source": "192.168.1.15"},
            {"id": 2, "severity": "Medium", "message": "Suspicious network activity", "timestamp": "2023-08-19 09:15:22", "source": "10.0.0.42"},
            {"id": 3, "severity": "Low", "message": "Unusual process activity", "timestamp": "2023-08-19 08:45:11", "source": "172.16.0.23"}
        ]
        
        alert_rows = []
        for alert in alerts_data:
            badge_color = "danger" if alert["severity"] == "High" else "warning" if alert["severity"] == "Medium" else "info"
            
            row = dbc.ListGroupItem(
                [
                    dbc.Row(
                        [
                            dbc.Col(
                                dbc.Badge(alert["severity"], color=badge_color, className="me-1"),
                                width=2
                            ),
                            dbc.Col(alert["message"], width=5),
                            dbc.Col(alert["source"], width=2),
                            dbc.Col(alert["timestamp"], width=3)
                        ]
                    )
                ],
                action=True,
                className="alert-item"
            )
            alert_rows.append(row)
        
        return dbc.Card(
            [
                dbc.CardHeader(
                    [
                        html.H4("Recent Alerts", className="d-inline"),
                        dbc.Badge(len(alerts_data), color="danger", className="ms-2")
                    ]
                ),
                dbc.CardBody(
                    [
                        dbc.ListGroup(alert_rows, flush=True)
                    ]
                )
            ]
        )