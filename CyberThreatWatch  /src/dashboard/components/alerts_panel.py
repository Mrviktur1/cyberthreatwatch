import dash_bootstrap_components as dbc
from dash import html, dcc, Output, Input, callback
from supabase import create_client, Client
import os


class AlertsPanel:
    def __init__(self):
        # Supabase connection
        self.url: str = os.getenv("SUPABASE_URL")
        self.key: str = os.getenv("SUPABASE_KEY")
        self.supabase: Client = create_client(self.url, self.key)

    def fetch_alerts(self, limit=10):
        """Fetch latest alerts from Supabase"""
        try:
            response = (
                self.supabase.table("alerts")
                .select("*")
                .order("timestamp", desc=True)
                .limit(limit)
                .execute()
            )
            return response.data or []
        except Exception as e:
            print("Error fetching alerts:", e)
            return []

    def layout(self):
        return dbc.Card(
            [
                dbc.CardHeader(
                    [
                        html.H4("Recent Alerts", className="d-inline"),
                        dbc.Badge(id="alerts-count", color="danger", className="ms-2"),
                    ]
                ),
                dbc.CardBody(
                    [
                        dbc.ListGroup(id="alerts-list", flush=True),
                        # Auto-refresh every 30 seconds
                        dcc.Interval(id="alerts-interval", interval=30 * 1000, n_intervals=0),
                    ]
                ),
            ]
        )


# === Dash Callbacks ===
@callback(
    Output("alerts-list", "children"),
    Output("alerts-count", "children"),
    Input("alerts-interval", "n_intervals"),
)
def update_alerts(n):
    """Refresh alerts list every 30 seconds"""
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY")
    supabase: Client = create_client(url, key)

    try:
        response = (
            supabase.table("alerts")
            .select("*")
            .order("timestamp", desc=True)
            .limit(10)
            .execute()
        )
        alerts_data = response.data or []
    except Exception as e:
        print("Error fetching alerts:", e)
        return [html.P("⚠️ Error loading alerts")], "0"

    alert_rows = []
    for alert in alerts_data:
        sev = alert.get("severity", "low").capitalize()
        badge_color = (
            "danger"
            if sev.lower() == "critical"
            else "warning"
            if sev.lower() in ["high", "medium"]
            else "info"
        )

        row = dbc.ListGroupItem(
            [
                dbc.Row(
                    [
                        dbc.Col(
                            dbc.Badge(sev, color=badge_color, className="me-1"),
                            width=2,
                        ),
                        dbc.Col(alert.get("rule", "Unknown Rule"), width=3),
                        dbc.Col(str(alert.get("details", {})), width=3),
                        dbc.Col(alert.get("technique", ""), width=2),
                        dbc.Col(str(alert.get("timestamp", "")), width=2),
                    ]
                )
            ],
            action=True,
            className="alert-item",
        )
        alert_rows.append(row)

    return alert_rows, str(len(alerts_data))
