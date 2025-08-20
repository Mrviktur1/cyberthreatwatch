import dash_bootstrap_components as dbc
from dash import html, dcc

class SettingsPage:
    def __init__(self):
        pass
    
    def layout(self):
        return html.Div(
            [
                html.H1("Settings", className="text-center mb-4"),
                dbc.Tabs(
                    [
                        dbc.Tab(
                            dbc.Card(
                                dbc.CardBody(
                                    [
                                        html.H4("General Settings"),
                                        dbc.Row(
                                            [
                                                dbc.Col(
                                                    dbc.Form(
                                                        [
                                                            dbc.Label("Time Zone"),
                                                            dcc.Dropdown(
                                                                id="timezone-selector",
                                                                options=[
                                                                    {"label": "UTC", "value": "utc"},
                                                                    {"label": "EST", "value": "est"},
                                                                    {"label": "PST", "value": "pst"},
                                                                    {"label": "CET", "value": "cet"}
                                                                ],
                                                                value="utc"
                                                            ),
                                                            html.Br(),
                                                            dbc.Label("Theme"),
                                                            dbc.RadioItems(
                                                                options=[
                                                                    {"label": "Light", "value": "light"},
                                                                    {"label": "Dark", "value": "dark"}
                                                                ],
                                                                value="light",
                                                                id="theme-selector"
                                                            )
                                                        ]
                                                    ),
                                                    width=6
                                                )
                                            ]
                                        )
                                    ]
                                )
                            ),
                            label="General"
                        ),
                        dbc.Tab(
                            dbc.Card(
                                dbc.CardBody(
                                    [
                                        html.H4("Data Sources"),
                                        dbc.Table(
                                            [
                                                html.Thead(
                                                    html.Tr(
                                                        [
                                                            html.Th("Name"),
                                                            html.Th("Type"),
                                                            html.Th("Status"),
                                                            html.Th("Actions")
                                                        ]
                                                    )
                                                ),
                                                html.Tbody(
                                                    [
                                                        html.Tr(
                                                            [
                                                                html.Td("Firewall Logs"),
                                                                html.Td("Syslog"),
                                                                html.Td(dbc.Badge("Active", color="success")),
                                                                html.Td(dbc.Button("Configure", size="sm"))
                                                            ]
                                                        ),
                                                        html.Tr(
                                                            [
                                                                html.Td("Server Events"),
                                                                html.Td("Windows Event Log"),
                                                                html.Td(dbc.Badge("Inactive", color="secondary")),
                                                                html.Td(dbc.Button("Configure", size="sm"))
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
                            ),
                            label="Data Sources"
                        ),
                        dbc.Tab(
                            dbc.Card(
                                dbc.CardBody(
                                    [
                                        html.H4("Alert Rules"),
                                        dbc.Button("Add New Rule", color="primary", className="mb-3"),
                                        dbc.Table(
                                            [
                                                html.Thead(
                                                    html.Tr(
                                                        [
                                                            html.Th("Rule Name"),
                                                            html.Th("Severity"),
                                                            html.Th("Enabled"),
                                                            html.Th("Actions")
                                                        ]
                                                    )
                                                ),
                                                html.Tbody(
                                                    [
                                                        html.Tr(
                                                            [
                                                                html.Td("Failed Login Attempts"),
                                                                html.Td(dbc.Badge("High", color="danger")),
                                                                html.Td(dbc.Switch(id="switch-1", value=True)),
                                                                html.Td(
                                                                    [
                                                                        dbc.Button("Edit", size="sm", color="info", className="me-1"),
                                                                        dbc.Button("Delete", size="sm", color="danger")
                                                                    ]
                                                                )
                                                            ]
                                                        ),
                                                        html.Tr(
                                                            [
                                                                html.Td("Unusual Network Traffic"),
                                                                html.Td(dbc.Badge("Medium", color="warning")),
                                                                html.Td(dbc.Switch(id="switch-2", value=True)),
                                                                html.Td(
                                                                    [
                                                                        dbc.Button("Edit", size="sm", color="info", className="me-1"),
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
                            ),
                            label="Alert Rules"
                        )
                    ]
                )
            ]
        )