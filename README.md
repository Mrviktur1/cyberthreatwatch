# cyberthreatwatch
CyberThreatWatch 🔍: A real-time cybersecurity dashboard tracking CVEs, malware, and phishing threats. Integrates NVD/OTX APIs, sends email/Slack alerts, and features an interactive Streamlit UI. Deployable via Docker or Streamlit Cloud. #cybersecurity #threatintel
## 💻 Featured Code Sample: Secure Authentication & Threat Intelligence Dashboard

This project implements a **real-time threat intelligence platform** combining:

- 🧠 **Supabase Authentication** — Magic link, session expiry, MFA setup & verification  
- 🔒 **Secure Architecture** — Session management, rate-limiting, validation, and error handling  
- 🧩 **Threat Intelligence Visualization** — Real-time data from OTX, processed and displayed via Streamlit  
- 📊 **Analytics** — Dynamic metrics, charts (Plotly), and GeoIP mapping  

---

### 🔐 Authentication Module – [`auth.py`](./dashboard/components/auth.py)
Handles secure login, MFA enrollment/verification, and session management.

**Highlights:**
- Magic link login using Supabase  
- TOTP-based MFA with QR provisioning  
- Session expiry validation and secure logout  
- Comprehensive error handling & user feedback

---

### 🛡️ Threat Intelligence Panel – [`threat_intel.py`](./dashboard/components/threat_intel.py)
Processes and visualizes aggregated threat intelligence.

**Highlights:**
- Data normalization & enrichment  
- Dynamic dataframe rendering  
- Summary metrics (count, average threat score)  
- Refreshable Streamlit UI

---

### 🧭 Main Application – [`app.py`](./app.py)
Integrates authentication, analytics, and visualizations into one cohesive dashboard.

**Highlights:**
- Streamlit UI layout with modular components  
- Real-time OTX data ingestion  
- Supabase database interaction  
- Interactive charts, metrics, and GeoIP mapping

---

### 🧰 Tech Stack
- 🐍 **Python 3.11+**  
- 🎨 **Streamlit**  
- ☁️ **Supabase** (Auth + DB)  
- 📊 **Plotly** for charts  
- 🛰️ **OTXv2 API** for threat data  
- 🔐 **PyOTP** for MFA  

---

### 🚀 Run Locally
```bash
pip install -r requirements.txt
streamlit run app.py
