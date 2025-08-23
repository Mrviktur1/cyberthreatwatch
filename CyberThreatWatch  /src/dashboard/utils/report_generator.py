from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from datetime import datetime
import pandas as pd
import os
import matplotlib.pyplot as plt

class ReportGenerator:
    def __init__(self, logo_path="assets/CyberThreatWatch.png"):
        self.logo_path = logo_path

    def _generate_chart(self, df: pd.DataFrame, column: str, output_file: str, title: str):
        """Generate a bar chart and save as PNG."""
        if column not in df.columns or df.empty:
            return None

        counts = df[column].value_counts()
        plt.figure(figsize=(5,3))
        counts.plot(kind="bar")
        plt.title(title)
        plt.xlabel(column)
        plt.ylabel("Count")
        plt.tight_layout()
        plt.savefig(output_file)
        plt.close()
        return output_file

    def _build_executive_summary(self, alerts: pd.DataFrame, styles):
        """Generate executive summary elements."""
        elements = []
        total_alerts = len(alerts)

        if total_alerts > 0:
            severity_counts = alerts["severity"].value_counts().to_dict()
            most_common_ip = alerts["source_ip"].value_counts().idxmax() if "source_ip" in alerts else "N/A"
            time_range = f"{alerts['timestamp'].min()} → {alerts['timestamp'].max()}" if "timestamp" in alerts else "N/A"

            elements.append(Paragraph("<b>Executive Summary</b>", styles['Heading1']))
            elements.append(Spacer(1, 12))
            elements.append(Paragraph(f"📊 Total Alerts: <b>{total_alerts}</b>", styles['Normal']))
            elements.append(Paragraph(f"⚠️ Severity Breakdown: {severity_counts}", styles['Normal']))
            elements.append(Paragraph(f"🌍 Most Frequent Source IP: <b>{most_common_ip}</b>", styles['Normal']))
            elements.append(Paragraph(f"🗓️ Date Range: {time_range}", styles['Normal']))
            elements.append(Spacer(1, 24))
        else:
            elements.append(Paragraph("<b>Executive Summary</b>", styles['Heading1']))
            elements.append(Paragraph("No alerts available during this reporting period.", styles['Normal']))
            elements.append(Spacer(1, 24))

        return elements

    def _build_analyst_notes(self, styles, notes=""):
        """Generate analyst notes section."""
        elements = []
        elements.append(Paragraph("<b>Analyst Notes</b>", styles['Heading1']))
        elements.append(Spacer(1, 12))

        if notes.strip():
            elements.append(Paragraph(notes, styles['Normal']))
        else:
            elements.append(Paragraph("No analyst notes provided for this report.", styles['Italic']))

        elements.append(Spacer(1, 24))
        return elements

    def generate_pdf(self, alerts: pd.DataFrame, output_path="incident_report.pdf", analyst_notes=""):
        doc = SimpleDocTemplate(output_path, pagesize=A4)
        styles = getSampleStyleSheet()
        elements = []

        # --- Header ---
        if os.path.exists(self.logo_path):
            elements.append(RLImage(self.logo_path, width=100, height=100))
        elements.append(Paragraph("<b>CyberThreatWatch Incident Report</b>", styles['Title']))
        elements.append(Spacer(1, 12))
        elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 24))

        # --- Executive Summary ---
        elements.extend(self._build_executive_summary(alerts, styles))
        elements.append(PageBreak())

        # --- Alerts Table ---
        if not alerts.empty:
            table_data = [alerts.columns.tolist()] + alerts.astype(str).values.tolist()
            table = Table(table_data, repeatRows=1)
            table.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), colors.black),
                ("TEXTCOLOR", (0,0), (-1,0), colors.white),
                ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
                ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
                ("ALIGN", (0,0), (-1,-1), "CENTER"),
                ("BACKGROUND", (0,1), (-1,-1), colors.whitesmoke),
            ]))
            elements.append(Paragraph("<b>Alerts Table</b>", styles['Heading2']))
            elements.append(table)
            elements.append(Spacer(1, 24))
        else:
            elements.append(Paragraph("No alerts available.", styles['Normal']))

        # --- Charts ---
        if not alerts.empty:
            charts = [
                ("severity", "Alerts by Severity", "alerts_by_severity.png"),
                ("source_ip", "Alerts by Source IP", "alerts_by_source.png")
            ]

            for col, title, filename in charts:
                chart_path = self._generate_chart(alerts, col, filename, title)
                if chart_path and os.path.exists(chart_path):
                    elements.append(Paragraph(f"<b>{title}</b>", styles['Heading2']))
                    elements.append(RLImage(chart_path, width=400, height=250))
                    elements.append(Spacer(1, 24))

        # --- Analyst Notes ---
        elements.append(PageBreak())
        elements.extend(self._build_analyst_notes(styles, analyst_notes))

        # Build PDF
        doc.build(elements)
        return output_path
