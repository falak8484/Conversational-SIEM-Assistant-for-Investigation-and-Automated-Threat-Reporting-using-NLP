"""
Conversational SIEM Assistant - Backend Server
FastAPI-based local SIEM with real log collection, NLP chatbot, and reporting
"""

import os
import sys
import re
import platform
import subprocess
import sqlite3
import threading
import socket
import json
import math
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pathlib import Path
import asyncio

from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH  = BASE_DIR / "data" / "events.db"
FRONTEND_DIR = BASE_DIR / "frontend"

# ─── App ──────────────────────────────────────────────────────────────────────
app = FastAPI(title="SIEM Assistant", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

@app.get("/", response_class=HTMLResponse)
async def root():
    index = FRONTEND_DIR / "index.html"
    return HTMLResponse(content=index.read_text(), status_code=200)

# ─── Global collection state ──────────────────────────────────────────────────
collection_state: Dict[str, Any] = {
    "running": False,
    "progress": 0,
    "status": "Idle",
    "total_collected": 0,
    "errors": [],
}

# ─── Database ─────────────────────────────────────────────────────────────────
def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            device_id   TEXT,
            hostname    TEXT,
            event_type  TEXT NOT NULL,
            severity    TEXT NOT NULL,
            username    TEXT,
            ip_address  TEXT,
            message     TEXT NOT NULL,
            raw_log     TEXT,
            created_at  TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp  ON events(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_event_type ON events(event_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ip         ON events(ip_address)")
    conn.commit()
    conn.close()
    _purge_old_events()

def _purge_old_events():
    cutoff = (datetime.utcnow() - timedelta(days=30)).isoformat()
    conn = get_db()
    conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
    conn.commit()
    conn.close()

# ─── Log parsers ──────────────────────────────────────────────────────────────
HOSTNAME = socket.gethostname()
DEVICE_ID = f"{HOSTNAME}-{platform.system()}"

# Patterns for real security events
PATTERNS = {
    "failed_login": [
        re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)", re.I),
        re.compile(r"authentication failure.*user=(\S+)", re.I),
        re.compile(r"FAILED LOGIN.*for user[: ]+(\S+)", re.I),
        re.compile(r"Invalid user (\S+) from ([\d.]+)", re.I),
        re.compile(r"pam_unix.*auth failure.*user=(\S+)", re.I),
        re.compile(r"Login incorrect.*\((\S+)\)", re.I),
        re.compile(r"Failed to authenticate user[: ]+(\S+)", re.I),
        # macOS
        re.compile(r"Authorization.*deny.*user[= ](\S+)", re.I),
        re.compile(r"com\.apple\.authd.*failed.*user[= ](\S+)", re.I),
    ],
    "successful_login": [
        re.compile(r"Accepted (?:password|publickey|keyboard-interactive) for (\S+) from ([\d.]+)", re.I),
        re.compile(r"session opened for user (\S+)", re.I),
        re.compile(r"pam_unix.*session.*opened.*user=(\S+)", re.I),
        re.compile(r"Successful login.*user[: ]+(\S+)", re.I),
        # macOS
        re.compile(r"com\.apple\.authd.*succeeded.*user[= ](\S+)", re.I),
        re.compile(r"Login successful.*\((\S+)\)", re.I),
    ],
    "privilege_escalation": [
        # macOS/Linux sudo log: "sudo[5879]: vk : TTY=ttys015 ; PWD=... ; USER=root ; COMMAND=..."
        # The invoking user comes RIGHT AFTER "sudo[PID]: " — capture that, not USER=root
        re.compile(r"sudo\[\d+\]:\s+(\S+)\s+:.*COMMAND=(.+)", re.I),
        re.compile(r"sudo:\s+(\S+)\s+:.*COMMAND=(.+)", re.I),
        # fallback: any sudo line with COMMAND=
        re.compile(r"sudo.*?:\s+([A-Za-z0-9._-]+)\s+:.*COMMAND=(.+)", re.I),
        re.compile(r"su: \+.*:(\S+)->", re.I),
        re.compile(r"ROOTSHELL.*user[= ](\S+)", re.I),
    ],
    "access_denied": [
        re.compile(r"Permission denied.*user[= ]?(\S+)", re.I),
        re.compile(r"ACCESS DENIED.*user[= ]?(\S+)", re.I),
        re.compile(r"Illegal user (\S+) from ([\d.]+)", re.I),
        re.compile(r"POSSIBLE BREAK-IN ATTEMPT.*from ([\d.]+)", re.I),
        re.compile(r"maximum authentication attempts.*user (\S+)", re.I),
    ],
    "vpn_activity": [
        re.compile(r"(?:vpn|openvpn|wireguard|ipsec).*(?:connected|disconnected|authenticated).*user[= ]?(\S+)", re.I),
        re.compile(r"IKE.*authenticated.*(\S+@\S+)", re.I),
        re.compile(r"PPP.*(?:connect|disconnect).*user[= ]?(\S+)", re.I),
    ],
    "malware_detected": [
        re.compile(r"(?:virus|malware|trojan|spyware|ransomware|rootkit).*detected.*file[= ]?(\S+)", re.I),
        re.compile(r"ClamAV.*FOUND.*(\S+\.(?:exe|sh|py|bin))", re.I),
        re.compile(r"THREAT.*detected.*(\S+)", re.I),
    ],
}

IP_RE  = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
USER_RE = re.compile(r"user[= ](\S+)|for user (\S+)|for (\S+) from", re.I)

NOISE_PATTERNS = [
    re.compile(p, re.I) for p in [
        r"com\.apple\.(coreaudio|coredata|cloudkit|syncdefaultsd|bird|nsurlsessiond)",
        r"kernel.*Wake reason",
        r"diskarbitrationd",
        r"mds_stores",
        r"WindowServer",
        r"com\.apple\.xpc",
        r"backupd",
        r"Sandbox.*allow",
        r"tccd.*allow",
        r"securityd.*client",
        r"systemstats",
        r"cfprefsd",
        r"\[system\]\[S-1\]",   # generic system events
    ]
]

SEVERITY_MAP = {
    "malware_detected":   "critical",
    "privilege_escalation": "high",
    "access_denied":      "high",
    "failed_login":       "medium",
    "successful_login":   "low",
    "vpn_activity":       "low",
}

def is_noise(line: str) -> bool:
    return any(p.search(line) for p in NOISE_PATTERNS)

def parse_log_line(line: str) -> Optional[Dict]:
    """Try to classify a log line into a security event."""
    if not line.strip() or is_noise(line):
        return None

    line_clean = line.strip()

    for event_type, patterns in PATTERNS.items():
        for pat in patterns:
            m = pat.search(line_clean)
            if m:
                groups = m.groups()
                username = None
                ip_addr  = None
                extra    = {}

                if event_type in ("failed_login", "successful_login", "access_denied"):
                    username = groups[0] if groups and groups[0] else None
                    ip_addr  = groups[1] if len(groups) > 1 and groups[1] else None

                elif event_type == "privilege_escalation":
                    # groups[0] = invoking user (e.g. "vk"), groups[1] = command path
                    username = groups[0] if groups and groups[0] else None
                    # Extract the command run for the message enrichment
                    if len(groups) > 1 and groups[1]:
                        cmd_run = groups[1].strip()
                        extra["sudo_command"] = cmd_run[:120]

                elif event_type == "vpn_activity":
                    username = groups[0] if groups and groups[0] else None

                # Reject system/daemon pseudo-users
                SYSTEM_USERS = {"root", "_windowserver", "_mdnsresponder", "_spotlight",
                                 "daemon", "nobody", "www", "_www", "system", "SYSTEM",
                                 "_locationd", "_netbios", "_coreaudiod"}

                # For sudo: username is the person who RAN sudo, never "root"
                # If we accidentally captured root, try to find the real user via TTY owner
                if event_type == "privilege_escalation" and username in ("root", None):
                    # Try alternate extraction: look for pattern before " :"
                    alt = re.search(r"sudo\S*\s+([A-Za-z0-9._-]+)\s+:", line_clean)
                    if alt and alt.group(1) not in SYSTEM_USERS:
                        username = alt.group(1)

                # fallback IP extraction
                if ip_addr is None:
                    ip_m = IP_RE.search(line_clean)
                    if ip_m:
                        candidate = ip_m.group(1)
                        parts = candidate.split(".")
                        # skip loopback, link-local, private broadcast
                        if not candidate.startswith("127.") and candidate != "0.0.0.0":
                            ip_addr = candidate

                # clean username
                if username:
                    username = username.strip("():,;[]")
                    if len(username) > 64 or username in ("-", "NULL", "none", ""):
                        username = None

                # Build enriched message for sudo events
                msg = line_clean[:1000]
                if event_type == "privilege_escalation" and extra.get("sudo_command"):
                    cmd_short = extra["sudo_command"].split("/")[-1][:60]
                    msg = f"sudo by {username or '?'} → {cmd_short} | {line_clean[:600]}"

                return {
                    "event_type":  event_type,
                    "severity":    SEVERITY_MAP.get(event_type, "medium"),
                    "username":    username,
                    "ip_address":  ip_addr,
                    "message":     msg,
                    "raw_log":     line_clean[:2000],
                }

    return None

# Pre-compiled single-pass timestamp pattern (fastest approach)
_TS_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"          # ISO / macOS
    r"|(\w{3}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2})"          # syslog BSD
)
_NOW_YEAR = datetime.utcnow().year

def extract_timestamp_from_line(line: str) -> Optional[str]:
    """Single-pass timestamp extraction — fast."""
    m = _TS_RE.search(line)
    if not m:
        return None
    iso, syslog = m.group(1), m.group(2)
    try:
        if iso:
            return iso.replace(" ", "T")[:19]
        if syslog:
            dt = datetime.strptime(f"{_NOW_YEAR} {syslog.strip()}", "%Y %b %d %H:%M:%S")
            if dt > datetime.utcnow() + timedelta(days=1):
                dt = dt.replace(year=_NOW_YEAR - 1)
            return dt.isoformat()
    except Exception:
        pass
    return None

# ─── Platform log collectors ──────────────────────────────────────────────────
def _macos_last_hours(days: int) -> int:
    """Convert days to hours for macOS --last flag."""
    return max(1, days * 24)

def collect_macos(since: datetime, progress_cb) -> List[Dict]:
    events = []
    days = max(1, (datetime.utcnow() - since).days + 1)
    hours = _macos_last_hours(days)

    # ── Step 1: Fast path — `last` + `lastb` for login history (~instant) ──────
    progress_cb(8, "Fetching login history (last/lastb)…")

    def parse_last_output(lines, event_type):
        found = []
        cutoff = since.replace(tzinfo=None)
        for line in lines:
            line = line.strip()
            if not line or line.startswith("wtmp") or line.startswith("btmp") \
               or line.startswith("reboot") or line.startswith("shutdown"):
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            username = parts[0]
            # Skip system pseudo-users
            if username in ("reboot", "shutdown", "runlevel", "LOGIN", "root"):
                if event_type == "successful_login":
                    continue  # skip root auto-logins; keep for failed
            host_field = parts[2] if len(parts) > 2 else ""
            ip_addr = host_field if re.match(r"^\d+\.\d+", host_field) else None

            # macOS `last -F` date format: "Sun Apr 20 04:01:21 2026"
            # Try multiple formats
            dt = None
            for fmt, idx_end in [("%a %b %d %H:%M:%S %Y", 8), ("%a %b  %d %H:%M:%S %Y", 8)]:
                date_str = " ".join(parts[3:idx_end]) if len(parts) >= idx_end else ""
                try:
                    dt = datetime.strptime(date_str.strip(), fmt)
                    break
                except ValueError:
                    pass

            if dt is None:
                # fallback: scan the line for any timestamp
                ts = extract_timestamp_from_line(line)
                if ts:
                    try: dt = datetime.fromisoformat(ts)
                    except: continue
                else:
                    continue

            if dt < cutoff:
                continue

            found.append({
                "event_type": event_type,
                "severity":   SEVERITY_MAP.get(event_type, "low"),
                "timestamp":  dt.isoformat(),
                "username":   username,
                "ip_address": ip_addr,
                "message":    line[:400],
                "raw_log":    line,
            })
        return found

    try:
        r = subprocess.run(["last", "-F"], capture_output=True, text=True, timeout=10, errors="replace")
        events.extend(parse_last_output(r.stdout.splitlines(), "successful_login"))
    except Exception:
        pass

    # lastb = failed login attempts (requires root on some systems, silent fail is OK)
    try:
        r = subprocess.run(["lastb", "-F"], capture_output=True, text=True, timeout=10, errors="replace")
        if r.returncode == 0 and r.stdout.strip():
            events.extend(parse_last_output(r.stdout.splitlines(), "failed_login"))
    except Exception:
        pass

    progress_cb(18, f"Login history: {len(events)} login events found")

    # ── Step 2: `log show` — sudo/auth events via tight process filter ─────────
    progress_cb(22, f"Scanning security logs (last {hours}h)…")

    # Broad process filter but NO message filter — let parse_log_line decide.
    # Avoids missing events due to case/wording differences.
    predicate = (
        'process == "sshd" OR process == "sudo" OR process == "su" '
        'OR process == "login" OR process == "openvpn" OR process == "screensaver" '
        'OR process == "SecurityAgent" OR process == "authorization"'
    )

    cmd = [
        "log", "show",
        "--last", f"{hours}h",
        "--predicate", predicate,
        "--style", "syslog",
        "--info",
    ]

    MAX_LINES = 12000

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=65536,
            text=True, errors="replace"
        )
        lines_processed = 0
        for line in proc.stdout:
            lines_processed += 1
            if lines_processed > MAX_LINES:
                proc.kill()
                break
            if lines_processed % 400 == 0:
                pct = min(78, 22 + int(lines_processed / MAX_LINES * 55))
                progress_cb(pct, f"Scanned {lines_processed} log entries…")

            ev = parse_log_line(line)
            if ev:
                ts = extract_timestamp_from_line(line) or datetime.utcnow().isoformat()
                ev["timestamp"] = ts
                events.append(ev)

        proc.wait(timeout=5)
        progress_cb(82, f"log show: {lines_processed} lines scanned, {len(events)} events total")

    except FileNotFoundError:
        progress_cb(82, "log command not found — using fallback")
        events.extend(_read_file_logs(["/var/log/system.log"], since, progress_cb))
    except Exception as exc:
        progress_cb(82, f"log show warning: {exc}")

    # ── Step 3: /var/log/install.log for any extra hints (tiny file) ─────────
    events.extend(_read_file_logs(["/var/log/install.log"], since, progress_cb))

    # De-duplicate by (timestamp, event_type, username)
    seen = set()
    unique = []
    for ev in events:
        key = (ev.get("timestamp",""), ev.get("event_type",""), ev.get("username",""))
        if key not in seen:
            seen.add(key)
            unique.append(ev)

    progress_cb(85, f"Collected {len(unique)} unique security events")
    return unique


def _read_file_logs(paths: List[str], since: datetime, progress_cb) -> List[Dict]:
    events = []
    since_ts = since.isoformat()
    for path in paths:
        p = Path(path)
        if not p.exists():
            continue
        progress_cb(None, f"Reading {path}…")
        try:
            size = p.stat().st_size
            read = 0
            with open(p, "r", errors="replace") as f:
                for line in f:
                    read += len(line)
                    ts = extract_timestamp_from_line(line)
                    if ts and ts < since_ts:
                        continue
                    ev = parse_log_line(line)
                    if ev:
                        ev["timestamp"] = ts or datetime.utcnow().isoformat()
                        events.append(ev)
        except PermissionError:
            progress_cb(None, f"Permission denied: {path} — try running with sudo")
        except Exception as e:
            progress_cb(None, f"Error reading {path}: {e}")
    return events


def collect_linux(since: datetime, progress_cb) -> List[Dict]:
    log_files = [
        "/var/log/auth.log",
        "/var/log/auth.log.1",
        "/var/log/secure",
        "/var/log/syslog",
        "/var/log/messages",
    ]
    progress_cb(5, "Scanning Linux log files…")
    events = _read_file_logs(log_files, since, progress_cb)
    progress_cb(85, f"Collected {len(events)} security events from Linux logs")
    return events


def collect_windows(since: datetime, progress_cb) -> List[Dict]:
    """Collect Windows Security Event Log using wevtutil."""
    events = []
    since_str = since.strftime("%Y-%m-%dT%H:%M:%S")
    # Event IDs: 4624=login, 4625=fail, 4648=explicit creds, 4688=new process, 4720=account created
    queries = {
        "failed_login": "4625",
        "successful_login": "4624",
        "privilege_escalation": "4648,4672",
        "access_denied": "4771,4776",
    }
    progress_cb(5, "Querying Windows Event Log…")

    for event_type, event_ids in queries.items():
        for eid in event_ids.split(","):
            query = f"*[System[EventID={eid} and TimeCreated[@SystemTime>='{since_str}']]]"
            cmd = ["wevtutil", "qe", "Security", f"/q:{query}", "/f:Text", "/rd:true", "/c:1000"]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, errors="replace")
                if result.returncode == 0:
                    for block in result.stdout.split("\r\n\r\n"):
                        if not block.strip():
                            continue
                        ts_m = re.search(r"Date:\s+(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", block)
                        ts = ts_m.group(1) if ts_m else datetime.utcnow().isoformat()
                        user_m = re.search(r"Account Name:\s+(\S+)", block)
                        ip_m   = re.search(r"Source Network Address:\s+([\d.]+)", block)
                        username = user_m.group(1) if user_m else None
                        ip_addr  = ip_m.group(1)  if ip_m  else None
                        if username in ("SYSTEM", "-", None):
                            continue
                        events.append({
                            "event_type": event_type,
                            "severity":   SEVERITY_MAP.get(event_type, "medium"),
                            "timestamp":  ts,
                            "username":   username,
                            "ip_address": ip_addr,
                            "message":    block.strip()[:800],
                            "raw_log":    block.strip()[:2000],
                        })
            except Exception:
                pass

    progress_cb(85, f"Collected {len(events)} events from Windows Event Log")
    return events


def collect_logs_task(days: int):
    """Background task: collect logs and write to DB."""
    global collection_state
    collection_state.update({"running": True, "progress": 0, "status": "Starting…",
                              "total_collected": 0, "errors": []})

    since = datetime.utcnow() - timedelta(days=days)

    def cb(pct, msg):
        if pct is not None:
            collection_state["progress"] = pct
        collection_state["status"] = msg

    try:
        cb(2, "Initialising database…")
        init_db()

        system = platform.system()
        cb(4, f"Detected OS: {system}")

        if system == "Darwin":
            events = collect_macos(since, cb)
        elif system == "Linux":
            events = collect_linux(since, cb)
        elif system == "Windows":
            events = collect_windows(since, cb)
        else:
            events = collect_linux(since, cb)  # best-effort

        cb(88, f"Storing {len(events)} events in database…")
        conn = get_db()
        conn.execute("PRAGMA synchronous = OFF")
        conn.execute("PRAGMA journal_mode = MEMORY")
        # Remove duplicates: wipe the window and re-insert
        since_iso = since.isoformat()
        conn.execute("DELETE FROM events WHERE timestamp >= ?", (since_iso,))
        # Bulk insert for speed
        rows = [
            (
                ev["timestamp"], DEVICE_ID, HOSTNAME,
                ev["event_type"], ev["severity"],
                ev.get("username"), ev.get("ip_address"),
                ev["message"], ev.get("raw_log"),
            )
            for ev in events
        ]
        conn.executemany(
            """INSERT INTO events
               (timestamp, device_id, hostname, event_type, severity,
                username, ip_address, message, raw_log)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            rows,
        )
        conn.commit()
        conn.close()

        _purge_old_events()

        collection_state.update({
            "running": False,
            "progress": 100,
            "status": f"Done — {len(events)} security events collected",
            "total_collected": len(events),
        })

    except Exception as exc:
        collection_state.update({
            "running": False,
            "progress": 100,
            "status": f"Error: {exc}",
            "errors": [str(exc)],
        })

# ─── Pydantic models ──────────────────────────────────────────────────────────
class CollectRequest(BaseModel):
    days: int = 1  # 1=24h, 7, 10, 30

class ChatRequest(BaseModel):
    message: str
    days: int = 7

# ─── API routes ───────────────────────────────────────────────────────────────
@app.post("/api/collect")
def api_collect(req: CollectRequest):
    if collection_state["running"]:
        raise HTTPException(status_code=409, detail="Collection already running")
    t = threading.Thread(target=collect_logs_task, args=(req.days,), daemon=True)
    t.start()
    return {"started": True, "days": req.days}

@app.get("/api/progress")
def api_progress():
    return collection_state

@app.get("/api/events")
def api_events(
    days: int = Query(7),
    event_type: Optional[str] = Query(None),
    limit: int = Query(500),
    offset: int = Query(0),
):
    since = (datetime.utcnow() - timedelta(days=days)).isoformat()
    conn = get_db()
    if event_type:
        rows = conn.execute(
            "SELECT * FROM events WHERE timestamp >= ? AND event_type = ? "
            "ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (since, event_type, limit, offset),
        ).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp >= ? AND event_type = ?",
            (since, event_type),
        ).fetchone()[0]
    else:
        rows = conn.execute(
            "SELECT * FROM events WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (since, limit, offset),
        ).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp >= ?", (since,)
        ).fetchone()[0]
    conn.close()
    return {
        "total": total,
        "events": [dict(r) for r in rows],
    }

@app.get("/api/stats")
def api_stats(days: int = Query(7)):
    since = (datetime.utcnow() - timedelta(days=days)).isoformat()
    conn = get_db()

    total = conn.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ?", (since,)).fetchone()[0]

    by_type = conn.execute(
        "SELECT event_type, COUNT(*) as cnt FROM events WHERE timestamp >= ? GROUP BY event_type ORDER BY cnt DESC",
        (since,),
    ).fetchall()

    by_severity = conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM events WHERE timestamp >= ? GROUP BY severity ORDER BY cnt DESC",
        (since,),
    ).fetchall()

    top_ips = conn.execute(
        "SELECT ip_address, COUNT(*) as cnt FROM events WHERE timestamp >= ? AND ip_address IS NOT NULL "
        "GROUP BY ip_address ORDER BY cnt DESC LIMIT 10",
        (since,),
    ).fetchall()

    top_users = conn.execute(
        "SELECT username, COUNT(*) as cnt FROM events WHERE timestamp >= ? AND username IS NOT NULL "
        "GROUP BY username ORDER BY cnt DESC LIMIT 10",
        (since,),
    ).fetchall()

    recent = conn.execute(
        "SELECT * FROM events WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT 5", (since,)
    ).fetchall()

    conn.close()
    return {
        "total": total,
        "by_type": [dict(r) for r in by_type],
        "by_severity": [dict(r) for r in by_severity],
        "top_ips": [dict(r) for r in top_ips],
        "top_users": [dict(r) for r in top_users],
        "recent": [dict(r) for r in recent],
    }

# ─── Chatbot (rule-based NLP, no hallucination) ───────────────────────────────
def _fmt_rows(rows, cols) -> str:
    if not rows:
        return "No results found."
    lines = []
    for r in rows:
        d = dict(r)
        lines.append("  • " + "  |  ".join(f"{c}: {d.get(c, '—')}" for c in cols))
    return "\n".join(lines)

def chat_logic(msg: str, days: int) -> str:
    since = (datetime.utcnow() - timedelta(days=days)).isoformat()
    conn = get_db()
    q = msg.lower().strip()

    try:
        # ── failed logins ──────────────────────────────────────────────────────
        if any(k in q for k in ["failed login", "fail", "bad password", "brute"]):
            rows = conn.execute(
                "SELECT timestamp, username, ip_address, message FROM events "
                "WHERE timestamp >= ? AND event_type='failed_login' ORDER BY timestamp DESC LIMIT 20",
                (since,),
            ).fetchall()
            count = conn.execute(
                "SELECT COUNT(*) FROM events WHERE timestamp >= ? AND event_type='failed_login'", (since,)
            ).fetchone()[0]
            if not rows:
                return f"✅ No failed login attempts found in the last {days} day(s)."
            result = f"🔴 **{count} failed login attempt(s)** in the last {days} day(s).\n\n"
            result += _fmt_rows(rows[:10], ["timestamp", "username", "ip_address"])
            return result

        # ── successful logins ──────────────────────────────────────────────────
        elif any(k in q for k in ["successful login", "logged in", "who logged", "last login", "success"]):
            rows = conn.execute(
                "SELECT timestamp, username, ip_address FROM events "
                "WHERE timestamp >= ? AND event_type='successful_login' ORDER BY timestamp DESC LIMIT 10",
                (since,),
            ).fetchall()
            if not rows:
                return f"No successful logins recorded in the last {days} day(s)."
            last = dict(rows[0])
            result = f"✅ **Last login**: {last.get('username','unknown')} at {last['timestamp']}"
            if last.get("ip_address"):
                result += f" from {last['ip_address']}"
            result += f"\n\nRecent logins ({min(len(rows),10)}):\n"
            result += _fmt_rows(rows[:10], ["timestamp", "username", "ip_address"])
            return result

        # ── top attack IPs ────────────────────────────────────────────────────
        elif any(k in q for k in ["top ip", "attack ip", "suspicious ip", "source ip", "attacker"]):
            rows = conn.execute(
                "SELECT ip_address, COUNT(*) as cnt, "
                "SUM(CASE WHEN event_type='failed_login' THEN 1 ELSE 0 END) as failed "
                "FROM events WHERE timestamp >= ? AND ip_address IS NOT NULL "
                "GROUP BY ip_address ORDER BY cnt DESC LIMIT 10",
                (since,),
            ).fetchall()
            if not rows:
                return "No IP addresses recorded in the selected time range."
            result = f"🌐 **Top source IPs** (last {days} day(s)):\n\n"
            for r in rows:
                d = dict(r)
                result += f"  • {d['ip_address']} — {d['cnt']} event(s), {d['failed']} failed login(s)\n"
            return result

        # ── privilege escalation / sudo ────────────────────────────────────────
        elif any(k in q for k in ["privilege", "sudo", "escalat", "root"]):
            rows = conn.execute(
                "SELECT timestamp, username, message FROM events "
                "WHERE timestamp >= ? AND event_type='privilege_escalation' ORDER BY timestamp DESC LIMIT 20",
                (since,),
            ).fetchall()
            if not rows:
                return f"No privilege escalation events in the last {days} day(s)."
            result = f"⚠️ **{len(rows)} privilege escalation event(s)**:\n\n"
            result += _fmt_rows(rows[:10], ["timestamp", "username", "message"])
            return result

        # ── suspicious activity ────────────────────────────────────────────────
        elif any(k in q for k in ["suspicious", "threat", "anomaly", "alert", "risk", "danger"]):
            # High/critical events
            rows = conn.execute(
                "SELECT event_type, timestamp, username, ip_address, message FROM events "
                "WHERE timestamp >= ? AND severity IN ('critical','high') ORDER BY timestamp DESC LIMIT 20",
                (since,),
            ).fetchall()
            counts = conn.execute(
                "SELECT event_type, COUNT(*) as cnt FROM events "
                "WHERE timestamp >= ? AND severity IN ('critical','high') GROUP BY event_type",
                (since,),
            ).fetchall()
            if not rows:
                return f"✅ No high-severity suspicious activity detected in the last {days} day(s)."
            summary = ", ".join(f"{dict(c)['event_type']}: {dict(c)['cnt']}" for c in counts)
            result = f"🚨 **Suspicious activity detected** [{summary}]:\n\n"
            result += _fmt_rows(rows[:15], ["event_type", "timestamp", "username", "ip_address"])
            return result

        # ── access denied ─────────────────────────────────────────────────────
        elif any(k in q for k in ["access denied", "permission denied", "denied"]):
            rows = conn.execute(
                "SELECT timestamp, username, ip_address, message FROM events "
                "WHERE timestamp >= ? AND event_type='access_denied' ORDER BY timestamp DESC LIMIT 20",
                (since,),
            ).fetchall()
            if not rows:
                return "No access denied events in the selected time range."
            result = f"🔒 **{len(rows)} access denied event(s)**:\n\n"
            result += _fmt_rows(rows[:10], ["timestamp", "username", "ip_address", "message"])
            return result

        # ── VPN ───────────────────────────────────────────────────────────────
        elif any(k in q for k in ["vpn", "tunnel", "remote access"]):
            rows = conn.execute(
                "SELECT timestamp, username, ip_address, message FROM events "
                "WHERE timestamp >= ? AND event_type='vpn_activity' ORDER BY timestamp DESC LIMIT 20",
                (since,),
            ).fetchall()
            if not rows:
                return "No VPN activity detected in the selected time range."
            result = f"🔑 **{len(rows)} VPN event(s)**:\n\n"
            result += _fmt_rows(rows[:10], ["timestamp", "username", "ip_address"])
            return result

        # ── malware ───────────────────────────────────────────────────────────
        elif any(k in q for k in ["malware", "virus", "trojan", "ransomware", "threat detected"]):
            rows = conn.execute(
                "SELECT timestamp, message FROM events "
                "WHERE timestamp >= ? AND event_type='malware_detected' ORDER BY timestamp DESC LIMIT 20",
                (since,),
            ).fetchall()
            if not rows:
                return "✅ No malware detections recorded in the selected time range."
            result = f"💀 **{len(rows)} malware detection(s)**:\n\n"
            result += _fmt_rows(rows[:10], ["timestamp", "message"])
            return result

        # ── summary / stats ────────────────────────────────────────────────────
        elif any(k in q for k in ["summary", "overview", "stats", "total", "count", "how many"]):
            row = conn.execute(
                "SELECT COUNT(*) as total,"
                " SUM(CASE WHEN event_type='failed_login' THEN 1 ELSE 0 END) as failed,"
                " SUM(CASE WHEN event_type='successful_login' THEN 1 ELSE 0 END) as success,"
                " SUM(CASE WHEN event_type='privilege_escalation' THEN 1 ELSE 0 END) as priv,"
                " SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as crit,"
                " SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) as high"
                " FROM events WHERE timestamp >= ?",
                (since,),
            ).fetchone()
            d = dict(row)
            return (
                f"📊 **Security Summary — last {days} day(s)**\n\n"
                f"  • Total events:          {d['total']}\n"
                f"  • Failed logins:         {d['failed']}\n"
                f"  • Successful logins:     {d['success']}\n"
                f"  • Privilege escalations: {d['priv']}\n"
                f"  • Critical severity:     {d['crit']}\n"
                f"  • High severity:         {d['high']}\n"
            )

        # ── generate report (redirect to /api/report) ──────────────────────────
        elif any(k in q for k in ["report", "generate report", "export"]):
            return "📄 Click the **Generate Report** button below to create a full threat report."

        # ── help ───────────────────────────────────────────────────────────────
        elif any(k in q for k in ["help", "what can you", "commands", "?"]):
            return (
                "🤖 **SIEM Assistant — Supported queries:**\n\n"
                "  • Show failed logins\n"
                "  • Who logged in last?\n"
                "  • Top attack IPs\n"
                "  • Show suspicious activity\n"
                "  • Privilege escalation events\n"
                "  • Access denied events\n"
                "  • VPN activity\n"
                "  • Malware detected\n"
                "  • Security summary / stats\n"
                "  • Generate report\n\n"
                "All answers are based strictly on collected logs — no guessing."
            )

        # ── unknown ────────────────────────────────────────────────────────────
        else:
            total = conn.execute(
                "SELECT COUNT(*) FROM events WHERE timestamp >= ?", (since,)
            ).fetchone()[0]
            if total == 0:
                return (
                    "⚠️ No logs collected yet. Click **Collect Logs** first, then ask me questions.\n\n"
                    "Type **help** to see supported queries."
                )
            return (
                f"I couldn't match that query to a known pattern.\n\n"
                f"There are **{total}** events in the last {days} day(s). "
                f"Type **help** to see what I can answer."
            )
    finally:
        conn.close()

@app.post("/api/chat")
def api_chat(req: ChatRequest):
    answer = chat_logic(req.message, req.days)
    return {"response": answer}

# ─── Report ───────────────────────────────────────────────────────────────────
@app.get("/api/report")
def api_report(days: int = Query(7)):
    since = (datetime.utcnow() - timedelta(days=days)).isoformat()
    conn = get_db()

    total = conn.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ?", (since,)).fetchone()[0]
    by_type = {r["event_type"]: r["cnt"] for r in conn.execute(
        "SELECT event_type, COUNT(*) as cnt FROM events WHERE timestamp >= ? GROUP BY event_type", (since,)
    ).fetchall()}
    by_sev = {r["severity"]: r["cnt"] for r in conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM events WHERE timestamp >= ? GROUP BY severity", (since,)
    ).fetchall()}
    top_ips = conn.execute(
        "SELECT ip_address, COUNT(*) as cnt FROM events WHERE timestamp >= ? AND ip_address IS NOT NULL "
        "GROUP BY ip_address ORDER BY cnt DESC LIMIT 10", (since,)
    ).fetchall()
    top_users = conn.execute(
        "SELECT username, COUNT(*) as cnt FROM events WHERE timestamp >= ? AND username IS NOT NULL "
        "GROUP BY username ORDER BY cnt DESC LIMIT 10", (since,)
    ).fetchall()
    timeline = conn.execute(
        "SELECT substr(timestamp,1,10) as day, COUNT(*) as cnt FROM events "
        "WHERE timestamp >= ? GROUP BY day ORDER BY day", (since,)
    ).fetchall()
    conn.close()

    # Build recommendations
    recs = []
    failed = by_type.get("failed_login", 0)
    priv   = by_type.get("privilege_escalation", 0)
    malw   = by_type.get("malware_detected", 0)
    crit   = by_sev.get("critical", 0)

    if failed > 10:
        recs.append(f"🔴 {failed} failed logins detected — consider enabling fail2ban or account lockout policies.")
    if failed > 50:
        recs.append("🔴 Possible brute-force attack in progress — review firewall rules and block offending IPs.")
    if priv > 0:
        recs.append(f"⚠️ {priv} privilege escalation event(s) — audit sudo usage and apply least-privilege principle.")
    if malw > 0:
        recs.append(f"💀 {malw} malware detection(s) — isolate affected systems immediately and run full scans.")
    if crit > 0:
        recs.append(f"🚨 {crit} critical-severity event(s) require immediate investigation.")
    if top_ips:
        recs.append(f"🌐 Top offending IP: {dict(top_ips[0])['ip_address']} ({dict(top_ips[0])['cnt']} events) — consider blocking.")
    if not recs:
        recs.append("✅ No critical threats detected. Continue monitoring.")

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "period_days": days,
        "hostname": HOSTNAME,
        "device_id": DEVICE_ID,
        "total_events": total,
        "by_type": by_type,
        "by_severity": by_sev,
        "top_ips": [dict(r) for r in top_ips],
        "top_users": [dict(r) for r in top_users],
        "timeline": [dict(r) for r in timeline],
        "recommendations": recs,
    }

# ─── Startup ──────────────────────────────────────────────────────────────────
@app.on_event("startup")
def startup():
    init_db()
    print(f"[SIEM] Database: {DB_PATH}")
    print(f"[SIEM] Frontend: {FRONTEND_DIR}")
    print(f"[SIEM] Platform: {platform.system()} / {HOSTNAME}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False)
