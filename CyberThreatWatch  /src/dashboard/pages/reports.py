import dash_bootstrap_components as dbc
from dash import html
from src.dashboard.components.reports import ReportsManager

class ReportsPage:
    def __init__(self):
        self.reports_manager = ReportsManager()
    
    def layout(self):
        return html.Div(
            [
                html.H1("Reports", className="text-center mb-4"),
                self.reports_manager.layout(),
                html.Hr(),
                html.H3("Report History"),
                dbc.Table(
                    [
                        html.Thead(
                            html.Tr(
                                [
                                    html.Th("Report Name"),
                                    html.Th("Date Generated"),
                                    html.Th("Actions")
                                ]
                            )
                        ),
                        html.Tbody(
                            [
                                html.Tr(
                                    [
                                        html.Td("Daily Summary - 2023-08-18"),
                                        html.Td("2023-08-19 08:30:45"),
                                        html.Td(
                                            [
                                                dbc.Button("Download", size="sm", color="primary", className="me-1"),
                                                dbc.Button("Delete", size="sm", color="danger")
                                            ]
                                        )
                                    ]
                                ),
                                html.Tr(
                                    [
                                        html.Td("Security Audit - Q2 2023"),
                                        html.Td("2023-07-01 14:22:10"),
                                        html.Td(
                                            [
                                                dbc.Button("Download", size="sm", color="primary", className="me-1"),
                                                dbc.Button("Delete", size="sm", color="danger")
                                            ]
                                        )
                                    ]
                                )
                            ]
                        )
                    ],
                    striped=True,
                    bordered=True,
                    hover=True
                )
            ]
        )