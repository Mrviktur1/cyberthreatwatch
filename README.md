# 🛡️ CyberThreatWatch  
**Real-Time Threat Intelligence Dashboard** — Powered by **Streamlit**, **Supabase**, and **AlienVault OTX**  

> A secure, data-driven cybersecurity dashboard featuring **Magic Link + MFA authentication**, **live threat intelligence**, and **interactive analytics**. Designed for analysts, researchers, and cybersecurity professionals.

---

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)
![Streamlit](https://img.shields.io/badge/Framework-Streamlit-red?logo=streamlit)
![Supabase](https://img.shields.io/badge/Backend-Supabase-3DDC84?logo=supabase)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

---

## 🔍 Overview

**CyberThreatWatch** is a **real-time threat intelligence platform** that helps organizations and analysts track, visualize, and report on active cyber threats.

Built with **Streamlit** and **Supabase**, it integrates **AlienVault OTX APIs** to fetch live indicators of compromise (IOCs) — including malware, phishing, and CVE data — while maintaining **secure authentication (Magic Link + MFA)** and **session control**.

### 🎯 Key Features
- 🔐 **Secure Authentication**: Supabase Magic Link + MFA (TOTP-based)
- 📡 **Live Threat Feeds**: Integration with **AlienVault OTX** and custom sources
- 📊 **Interactive Analytics**: Metrics, bar charts, pie charts, and time-series visualizations
- 🌍 **Global Map**: Real-time **GeoIP mapping** of source IPs
- 🧠 **Threat Scoring**: Automated ranking & normalization
- 📄 **Reporting**: Export alerts to CSV / PDF
- 🧩 **Modular Architecture**: Clean separation of components and utilities

---

## 🧱 Project Architecture


pip install -r requirements.txt
streamlit run app.py

cyberthreatwatch/
├── app.py # Main entry point (Streamlit app)
├── dashboard/
│ ├── components/
│ │ ├── auth.py # Secure login, magic link, MFA
│ │ ├── alerts_panel.py # Alerts visualization & filtering
│ │ ├── threat_intel.py # Threat intelligence table
│ │ └── login.py # Login UI component
│ ├── utils/
│ │ ├── otx_collector.py # Fetch OTX threat feeds
│ │ ├── geoip_helper.py # GeoIP lookup + caching
│ │ ├── report_generator.py # Generate PDF reports
│ │ └── helpers.py # Reusable utilities
│ └── init.py
├── assets/
│ ├── images/
│ └── screenshots/
├── Data/ # Sample datasets
├── requirements.txt
├── .streamlit/secrets.toml # Environment secrets (not committed)
└── README.md


---

## 🚀 Quick Start

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/Mrviktur1/cyberthreatwatch.git
cd cyberthreatwatch

Install Dependencies
pip install -r requirements.txt

Add Secrets
Create .streamlit/secrets.toml:
SUPABASE_URL = "https://yourproject.supabase.co"
SUPABASE_KEY = "your-supabase-api-key"
OTX_API_KEY  = "your-otx-api-key"

Run the Application
streamlit run app.py
Access the app locally: 👉 http://localhost:8501

📊 Dashboard Highlights
| Feature                 | Description                                |
| ----------------------- | ------------------------------------------ |
| 🔐 **Authentication**   | Magic link login + TOTP-based MFA          |
| 🧠 **Threat Analytics** | Dynamic dataframes, severity scoring       |
| 🌍 **Global Map**       | IP-to-location visualization (Mapbox)      |
| 📈 **Charts**           | Plotly graphs for severity, type, timeline |
| 🧾 **Reports**          | Download CSV / Generate analyst PDF        |
| 🔄 **Auto-Refresh**     | Live data sync every 60 seconds            |


🧩 Featured Code Samples

🔐 auth.py
Handles secure authentication with Supabase Magic Links, MFA enrollment & verification, and session expiry.

def enroll_mfa() -> bool:
    """Enrolls user into MFA with QR provisioning and code verification."""
    if not st.session_state.get("authenticated"):
        st.error("Please log in first.")
        return False
    st.session_state.mfa_secret = pyotp.random_base32()
    totp = pyotp.TOTP(st.session_state.mfa_secret)
    uri = totp.provisioning_uri(name=st.session_state.user_email, issuer_name="CyberThreatWatch")
    ...


🛡️ threat_intel.py
Processes and displays live threat data from OTX and Supabase.

df['duration_days'] = (
    pd.to_datetime(df['last_seen']) - pd.to_datetime(df['first_seen'])
).dt.days
st.dataframe(df.sort_values('threat_score', ascending=False))


🧭 app.py
Main Streamlit app — orchestrates UI, data ingestion, and analytics visualization.
Fetches alerts from OTX
Stores data in Supabase
Displays metrics, charts, and maps
Exports reports

🧰 Tech Stack
| Layer               | Tools                                 |
| ------------------- | ------------------------------------- |
| **Frontend**        | Streamlit                             |
| **Backend / DB**    | Supabase                              |
| **Data Sources**    | AlienVault OTX                        |
| **Security**        | PyOTP (MFA), HTTPS, Secret Management |
| **Visualization**   | Plotly, Mapbox                        |
| **Data Processing** | Pandas                                |
| **Reporting**       | ReportLab (PDF), CSV                  |
| **Language**        | Python 3.11+                          |


📸 Screenshots
(Add your actual screenshots under assets/screenshots/)
Dashboard Overview
Threat Map

📜 License
This project is licensed under the MIT License © 2025 Enemmoh Victor Okechukwu
