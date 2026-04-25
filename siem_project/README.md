# 🛡️ SIEM Assistant — Conversational Threat Intelligence Console

SIEM Assistant is a fully local, zero-cost Security Information and Event Management (SIEM) system that collects real system logs, detects security events, and allows users to investigate threats using natural language queries.

It simplifies complex log analysis by combining system-level data collection, parsing, and a chatbot interface into one easy-to-use tool.

---

## 🌐 Run the Application

👉 http://127.0.0.1:8000  
*(Runs locally on your system)*

---

## 🚀 Features

- 📡 Real system log collection (macOS, Linux, Windows)
- 🧠 Smart parsing of security events (failed logins, sudo, VPN, malware)
- 💬 Natural language chatbot (no query language needed)
- 📊 Threat detection and pattern analysis
- 📄 Automated security report generation
- 💾 SQLite storage with 30-day auto cleanup
- ⚡ Live progress bar during log collection
- 🔒 Fully local system (no cloud, no API, no data sharing)

---

## 💬 Example Queries


Show failed logins
Who logged in last?
Top attack IPs
Suspicious activity
Privilege escalation events
Access denied events
VPN activity
Malware detected
Security summary


---

## 🧠 How It Works

System Logs (OS)  
↓  
Log Collector  
↓  
Parser Engine  
↓  
SQLite Database  
↓  
FastAPI Backend  
↓  
Frontend Dashboard + Chatbot  

---

## ⚙️ Quick Start

### macOS / Linux
```bash
chmod +x run.sh
./run.sh
Windows
Double-click run.bat

Then open in browser:

http://127.0.0.1:8000