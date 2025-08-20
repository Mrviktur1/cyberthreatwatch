import dash_bootstrap_components as dbc
from dash import html, dcc, Input, Output, State, callback_context
import dash

class SearchBar:
    def __init__(self, app):
        self.app = app
        self.setup_callbacks()
    
    def layout(self):
        return dbc.Card(
            [
                dbc.CardBody(
                    [
                        html.H4("Search Events", className="card-title"),
                        dbc.Row(
                            [
                                dbc.Col(
                                    dcc.Input(
                                        id="search-input",
                                        type="text",
                                        placeholder="Enter search query...",
                                        className="form-control",
                                        style={"width": "100%"}
                                    ),
                                    width=9
                                ),
                                dbc.Col(
                                    dbc.Button(
                                        "Search",
                                        id="search-button",
                                        color="primary",
                                        n_clicks=0,
                                        style={"width": "100%"}
                                    ),
                                    width=3
                                )
                            ]
                        ),
                        html.Br(),
                        dbc.Row(
                            [
                                dbc.Col(
                                    dcc.Dropdown(
                                        id="time-range-dropdown",
                                        options=[
                                            {"label": "Last 15 minutes", "value": "15m"},
                                            {"label": "Last 1 hour", "value": "1h"},
                                            {"label": "Last 24 hours", "value": "24h"},
                                            {"label": "Last 7 days", "value": "7d"},
                                            {"label": "Custom", "value": "custom"}
                                        ],
                                        value="1h",
                                        clearable=False
                                    ),
                                    width=6
                                ),
                                dbc.Col(
                                    dcc.Dropdown(
                                        id="index-dropdown",
                                        options=[
                                            {"label": "All Data", "value": "all"},
                                            {"label": "Security Events", "value": "security"},
                                            {"label": "Network Logs", "value": "network"},
                                            {"label": "System Logs", "value": "system"}
                                        ],
                                        value="all",
                                        clearable=False
                                    ),
                                    width=6
                                )
                            ]
                        ),
                        html.Div(id="custom-time-range", style={"display": "none"})
                    ]
                )
            ]
        )
    
    def setup_callbacks(self):
        @self.app.callback(
            Output("custom-time-range", "style"),
            Input("time-range-dropdown", "value")
        )
        def show_custom_time_range(selected_range):
            if selected_range == "custom":
                return {"display": "block"}
            return {"display": "none"}