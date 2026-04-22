from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import sqlite3
import hashlib
import os
import re
import random
from datetime import datetime

app = Flask(__name__)
app.secret_key = "usms_secret_key_2024"
DB_PATH = "usms.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'viewer',
        is_locked INTEGER DEFAULT 0,
        failed_attempts INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS network_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        src_ip TEXT,
        dst_ip TEXT,
        port INTEGER,
        protocol TEXT,
        status TEXT,
        threat_type TEXT,
        logged_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS query_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        query TEXT,
        is_dangerous INTEGER DEFAULT 0,
        reason TEXT,
        logged_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")

    users = [
        ("admin",   hash_password("admin123"),   "admin"),
        ("alice",   hash_password("alice123"),   "user"),
        ("bob",     hash_password("bob123"),     "user"),
        ("charlie", hash_password("charlie123"), "guest"),
    ]
    for u in users:
        try:
            c.execute("INSERT INTO users (username, password, role) VALUES (?,?,?)", u)
        except:
            pass

    conn.commit()
    conn.close()

ROLE_PERMISSIONS = {
    "admin":  ["view_logs", "manage_users", "view_network", "view_queries", "add_user"],
    "user":   ["view_logs", "view_network", "view_queries"],
    "guest":  ["view_logs"],
}

def hash_password(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()

def can(role, permission):
    return permission in ROLE_PERMISSIONS.get(role, [])

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = hash_password(request.form["password"])
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()
        conn.close()

        if not user:
            error = "User not found."
        elif user["is_locked"]:
            error = "Account is locked. Contact admin."
        elif user["password"] != password:
            conn = get_db()
            attempts = user["failed_attempts"] + 1
            locked = 1 if attempts >= 3 else 0
            conn.execute(
                "UPDATE users SET failed_attempts=?, is_locked=? WHERE username=?",
                (attempts, locked, username)
            )
            conn.commit()
            conn.close()
            error = f"Wrong password. Attempt {attempts}/3."
        else:
            conn = get_db()
            conn.execute("UPDATE users SET failed_attempts=0 WHERE username=?", (username,))
            conn.commit()
            conn.close()
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


SUSPICIOUS_PORTS = [22, 23, 3389, 4444, 1433, 3306]
BLACKLISTED_IPS  = ["192.168.99.99", "10.0.0.254", "203.0.113.50"]

def analyze_packet(src_ip, dst_ip, port, protocol):
    threat = None
    status = "SAFE"
    if src_ip in BLACKLISTED_IPS:
        threat = "Blacklisted IP"
        status = "BLOCKED"
    elif port in SUSPICIOUS_PORTS:
        threat = f"Suspicious port {port}"
        status = "WARNING"
    conn = get_db()
    conn.execute(
        "INSERT INTO network_logs (src_ip, dst_ip, port, protocol, status, threat_type) VALUES (?,?,?,?,?,?)",
        (src_ip, dst_ip, port, protocol, status, threat)
    )
    conn.commit()
    conn.close()
    return {"src_ip": src_ip, "dst_ip": dst_ip, "port": port,
            "protocol": protocol, "status": status, "threat": threat}

def simulate_traffic():
    packets = [
        ("192.168.1.10", "192.168.1.1",   80,   "HTTP"),
        ("192.168.1.11", "8.8.8.8",        53,   "DNS"),
        ("192.168.99.99","192.168.1.1",    22,   "SSH"),   # attacker
        ("192.168.1.12", "192.168.1.1",    443,  "HTTPS"),
        ("203.0.113.50", "192.168.1.5",    3389, "RDP"),   # attacker
        ("10.0.0.5",     "10.0.0.1",       8080, "HTTP"),
    ]
    pkt = random.choice(packets)
    return analyze_packet(*pkt)


DANGEROUS_KEYWORDS = ["DROP", "DELETE", "TRUNCATE", "GRANT", "--", "1=1", "OR 1", "UNION"]

def audit_query(username, query):
    query_upper = query.upper()
    danger = any(kw in query_upper for kw in DANGEROUS_KEYWORDS)
    reason = None
    if danger:
        for kw in DANGEROUS_KEYWORDS:
            if kw in query_upper:
                reason = f"Contains '{kw}'"
                break
    conn = get_db()
    conn.execute(
        "INSERT INTO query_logs (username, query, is_dangerous, reason) VALUES (?,?,?,?)",
        (username, query, int(danger), reason)
    )
    conn.commit()
    conn.close()
    return {"query": query, "dangerous": danger, "reason": reason}


@app.route("/")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    role = session["role"]
    conn = get_db()
    net_logs   = conn.execute("SELECT * FROM network_logs ORDER BY logged_at DESC LIMIT 10").fetchall()
    query_logs = conn.execute("SELECT * FROM query_logs ORDER BY logged_at DESC LIMIT 10").fetchall()
    users      = conn.execute("SELECT id, username, role, is_locked, failed_attempts FROM users").fetchall()
    net_count  = conn.execute("SELECT COUNT(*) FROM network_logs WHERE status != 'SAFE'").fetchone()[0]
    sql_count  = conn.execute("SELECT COUNT(*) FROM query_logs WHERE is_dangerous=1").fetchone()[0]
    conn.close()
    return render_template("dashboard.html",
        username=session["username"], role=role,
        net_logs=net_logs, query_logs=query_logs, users=users,
        net_alerts=net_count, sql_alerts=sql_count,
        can=can
    )

@app.route("/add_user", methods=["POST"])
def add_user():
    if "username" not in session or not can(session["role"], "add_user"):
        return jsonify({"error": "Permission denied"}), 403
    u = request.form["username"]
    p = hash_password(request.form["password"])
    r = request.form["role"]
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username, password, role) VALUES (?,?,?)", (u, p, r))
        conn.commit()
        msg = f"User '{u}' added."
    except:
        msg = "Username already exists."
    conn.close()
    return jsonify({"message": msg})

@app.route("/unlock/<username>")
def unlock_user(username):
    if "username" not in session or session["role"] != "admin":
        return redirect(url_for("dashboard"))
    conn = get_db()
    conn.execute("UPDATE users SET is_locked=0, failed_attempts=0 WHERE username=?", (username,))
    conn.commit()
    conn.close()
    return redirect(url_for("dashboard"))

@app.route("/simulate_network")
def simulate_network():
    if "username" not in session:
        return jsonify({"error": "Not logged in"}), 401
    result = simulate_traffic()
    return jsonify(result)

@app.route("/audit_query", methods=["POST"])
def run_audit():
    if "username" not in session:
        return jsonify({"error": "Not logged in"}), 401
    query = request.form.get("query", "")
    result = audit_query(session["username"], query)
    return jsonify(result)


if __name__ == "__main__":
    init_db()
    print("\n========================================")
    print("  USMS - Unified Security Manager")
    print("  BTech Mini Project")
    print("  Open: http://localhost:5000")
    print("\n  Login: admin / admin123")
    print("========================================\n")
    app.run(debug=True, port=5000)
