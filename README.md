# 🛡️ SIEM Assistant — Conversational Threat Intelligence Console

A fully local Security Information and Event Management (SIEM) system that collects real system logs and allows investigation using a natural-language chatbot.

---

## 🚀 What This Project Does

* Collects real system logs from your machine
* Extracts security-related events (failed logins, sudo, VPN, malware)
* Stores logs in a local SQLite database
* Lets you query logs using simple language (no SIEM query language needed)
* Generates readable security reports

---

## 🧠 Example Queries

Show failed logins
Who logged in last
Top attacker IPs
Suspicious activity
Security summary

---

## ⚙️ How to Run

### macOS / Linux

```bash
chmod +x run.sh
./run.sh
```

### Windows

```bash
run.bat
```

Then open:

http://127.0.0.1:8000

---

## 📁 Project Structure

backend/ → FastAPI server + log parsing
frontend/ → UI dashboard
data/ → SQLite database
run.sh / run.bat → one-click startup

---

## 🔐 Security Note

* Runs fully on local machine
* No cloud or external API
* No data is shared

---

## 🧑‍💻 Author

Falak Shaikh
B.Tech Computer Science (Cyber Security)

---
