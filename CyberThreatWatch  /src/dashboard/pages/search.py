import dash_bootstrap_components as dbc
from dash import html, dcc
from src.dashboard.components.search_bar import SearchBar
from src.dashboard.components.data_visualizations import DataVisualizations

class SearchPage:
    def __init__(self, app):
        self.app = app
        self.search_bar = SearchBar(app)
        self.visualizations = DataVisualizations()
    
    def layout(self):
        return html.Div(
            [
                html.H1("Event Search", className="text-center mb-4"),
                self.search_bar.layout(),
                html.Hr(),
                html.H3("Search Results"),
                dbc.Spinner(html.Div(id="search-results")),
                html.Hr(),
                self.visualizations.layout()
            ]
        )