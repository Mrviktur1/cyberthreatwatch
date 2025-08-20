import dash_bootstrap_components as dbc
from dash import html, dcc
from datetime import datetime, timedelta

class ReportsManager:
    def __init__(self):
        pass
    
    def report_generator(self):
        return dbc.Card(
            [
                dbc.CardHeader(html.H4("Generate Report")),
                dbc.CardBody(
                    [
                        dbc.Row(
                            [
                                dbc.Col(
                                    dcc.Dropdown(
                                        id="report-type",
                                        options=[
                                            {"label": "Daily Summary", "value": "daily"},
                                            {"label": "Weekly Summary", "value": "weekly"},
                                            {"label": "Monthly Summary", "value": "monthly"},
                                            {"label": "Security Audit", "value": "audit"},
                                            {"label": "Compliance Report", "value": "compliance"}
                                        ],
                                        value="daily",
                                        clearable=False
                                    ),
                                    width=6
                                ),
                                dbc.Col(
                                    dcc.DatePickerRange(
                                        id="report-date-range",
                                        start_date=datetime.now() - timedelta(days=7),
                                        end_date=datetime.now(),
                                        display_format="YYYY-MM-DD"
                                    ),
                                    width=6
                                )
                            ]
                        ),
                        html.Br(),
                        dbc.Row(
                            [
                                dbc.Col(
                                    dbc.Button(
                                        "Generate PDF Report",
                                        color="danger",
                                        className="me-2"
                                    ),
                                    width=6
                                ),
                                dbc.Col(
                                    dbc.Button(
                                        "Generate CSV Export",
                                        color="success"
                                    ),
                                    width=6
                                )
                            ]
                        )
                    ]
                )
            ]
        )
    
    def layout(self):
        return self.report_generator()