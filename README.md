# unified-security-management-system
A Flask-based cybersecurity mini project that integrates Network Security Monitoring, Database Query Auditing, and Role-Based Access Control into one unified dashboard.
---

## How to Run

```bash
pip install flask
python app.py
```

Open: http://localhost:5000

---

## Login Credentials

| Username | Password     | Role  |
|----------|-------------|-------|
| admin    | admin123    | Admin |
| alice    | alice123    | User  |
| bob      | bob123      | User  |
| charlie  | charlie123  | Guest |

---

## Project Structure

```
usms/
├── app.py              ← All backend logic (Flask + SQLite)
├── requirements.txt    ← Just "flask"
├── usms.db             ← Auto-created on first run
└── templates/
    ├── login.html      ← Login page
    └── dashboard.html  ← Main dashboard
```

---

## Features

### Module 1 — Network Security Monitor
- Simulates network packets
- Detects blacklisted IPs and suspicious ports (22, 23, 3389, 4444, etc.)
- Classifies traffic as SAFE / WARNING / BLOCKED
- Logs all events to database

### Module 2 — Database Security Auditor
- Audit any SQL query for dangerous keywords
- Detects: DROP, DELETE, TRUNCATE, GRANT, SQL injection (1=1, OR 1, UNION, --)
- Logs all queries with username and timestamp

### Module 3 — Access Control (RBAC)
- Role-Based Access Control: Admin > User > Guest
- Password hashing with SHA-256
- Account lockout after 3 failed login attempts
- Admin can add users and unlock accounts
- Permission matrix enforced on every route

---
