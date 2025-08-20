import dash_bootstrap_components as dbc
from dash import html, dcc

class DashboardManager:
    def __init__(self):
        self.dashboards = {
            "overview": "Security Overview",
            "network": "Network Monitoring",
            "threats": "Threat Detection",
            "compliance": "Compliance Reporting"
        }
    
    def dashboard_selector(self):
        options = [{"label": name, "value": id} for id, name in self.dashboards.items()]
        
        return dbc.Card(
            [
                dbc.CardBody(
                    [
                        html.H4("Select Dashboard", className="card-title"),
                        dcc.Dropdown(
                            id="dashboard-selector",
                            options=options,
                            value="overview",
                            clearable=False
                        ),
                        html.Br(),
                        dbc.Button("Save Dashboard", color="success", className="me-2"),
                        dbc.Button("Export Dashboard", color="info")
                    ]
                )
            ]
        )
    
    def layout(self):
        return self.dashboard_selector()