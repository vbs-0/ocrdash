"""
LensIQ Management Server  (backend API + WebSocket)
===================================================
Run on the VM (129.159.20.37) on port 7788.

  pip install -r requirements.txt
  python mgmt_server.py            # or via pm2 (see ecosystem.config.js)

Responsibilities
  - Admin auth (dashboard logins)         POST /api/admin/login
  - Employee management + gate            /api/employees , /api/employee/verify
  - Config sync for the desktop tool      GET  /api/config
  - Per-employee usage telemetry          POST /api/usage  + summaries
  - Per-employee API key / model override (employees table)
  - Tool admin-panel password (shared)    /api/settings
  - Broadcast popups (realtime)           POST /api/broadcast  + /ws/*
  - Remote update push/upload/download    /api/updates/*
  - QR admin login                        /api/qr/*
  - Realtime fan-out                      WebSocket /ws/tool , /ws/admin

Design notes
  - SQLite (single file lensiq.db) — zero external DB.
  - Passwords stored as pbkdf2_hmac-sha256 with per-row salt (stdlib only).
  - Admin tokens = HMAC-signed compact tokens (stdlib hmac), 12h expiry.
  - Offline-first is a CLIENT concern: the tool caches the last /api/config and
    queues /api/usage locally; this server is stateless about client liveness.
"""

import os, sqlite3, hashlib, hmac, time, json, base64, secrets, threading
from typing import Optional
from fastapi import FastAPI, Request, UploadFile, File, Form, WebSocket, WebSocketDisconnect, Header, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# ── Paths / constants ─────────────────────────────────────────────────────────
BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "lensiq.db")
UPLOAD_DIR = os.path.join(BASE, "updates")
os.makedirs(UPLOAD_DIR, exist_ok=True)
PORT = int(os.environ.get("LENSIQ_MGMT_PORT", "7788"))

# Server secret (token signing). Override via env in production.
SECRET = os.environ.get("LENSIQ_SECRET", "lensiq-change-this-secret-in-prod").encode()
TOKEN_TTL = 12 * 3600

# The MASTER admin. ONLY this account can set the tool master password / grace
# period, and the dashboard shows the "Master Control" section only to it.
MASTER_EMAIL = "vbs"
SEED_ADMINS = [
    ("skylinx@gmail.com", "admin@159", "Skylinx Admin"),
    ("vbs@gmail.com", "admin@159", "VBS Admin"),
    (MASTER_EMAIL, "vbs@123", "VBS Master"),
]
DEFAULTS = {
    "tool_admin_password": "garuda123",   # shared admin-panel password on the tool
    "default_api_key": "",
    "default_api_key_2": "",               # fallback Gemini key (tried if primary fails)
    "default_model": "gemini-3.1-flash-lite",
    "default_fb1": "gemini-3.1-flash-lite",
    "default_fb2": "gemini-3.1-flash-lite",
    "google_sheets_url": "",
    "google_sheets_apps_script_url": "",
    "flag_uncertain": "1",                 # 1=on: mark low-confidence OCR chars with 🚩
    "flag_threshold": "90",                # confidence % below which chars are flagged
    "dedup_enabled": "1",                  # 1=on: reuse cached OCR for duplicate images
    "offline_grace_hours": "24",           # tool may run offline this long after a good verify
    # master_pw_hash is seeded separately in init_db() (hashed), default "vbs@123"
    "latest_version": "1.0.0",
    "update_filename": "",
    "update_notes": "",
    "update_pushed": "0",
    "broadcast_message": "",
    "broadcast_level": "info",
    "broadcast_id": "0",
}

_db_lock = threading.Lock()


# ── DB helpers ────────────────────────────────────────────────────────────────
def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def hash_pw(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120_000)
    return base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def verify_pw(password: str, stored: str) -> bool:
    try:
        salt_b64, dk_b64 = stored.split("$")
        salt = base64.b64decode(salt_b64)
        return hmac.compare_digest(hash_pw(password, salt), stored)
    except Exception:
        return False


def init_db():
    with _db_lock, db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS admins(
            id INTEGER PRIMARY KEY, email TEXT UNIQUE, name TEXT, pw TEXT);
        CREATE TABLE IF NOT EXISTS employees(
            id INTEGER PRIMARY KEY, employee_id TEXT UNIQUE, name TEXT,
            active INTEGER DEFAULT 1, api_key_override TEXT DEFAULT '',
            api_key2_override TEXT DEFAULT '',
            model_override TEXT DEFAULT '', google_sheets_url TEXT DEFAULT '',
            created_at INTEGER, last_seen INTEGER);
        CREATE TABLE IF NOT EXISTS usage(
            id INTEGER PRIMARY KEY, employee_id TEXT, ts INTEGER, engine TEXT,
            images INTEGER, records INTEGER, ocr_ms REAL, classify_ms REAL,
            session_duration INTEGER DEFAULT 0, manual_corrections INTEGER DEFAULT 0,
            offline_images INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS qr_tokens(
            token TEXT PRIMARY KEY, created INTEGER, status TEXT,
            admin_email TEXT, auth_token TEXT);
        CREATE TABLE IF NOT EXISTS update_history(
            id INTEGER PRIMARY KEY, version TEXT, filename TEXT, notes TEXT,
            size INTEGER, uploaded_at INTEGER, pushed INTEGER DEFAULT 0);
        """)
        # Run migrations for enhanced analytics
        try: c.execute("ALTER TABLE usage ADD COLUMN session_duration INTEGER DEFAULT 0")
        except Exception: pass
        try: c.execute("ALTER TABLE usage ADD COLUMN manual_corrections INTEGER DEFAULT 0")
        except Exception: pass
        try: c.execute("ALTER TABLE usage ADD COLUMN offline_images INTEGER DEFAULT 0")
        except Exception: pass
        try: c.execute("ALTER TABLE employees ADD COLUMN google_sheets_url TEXT DEFAULT ''")
        except Exception: pass
        try: c.execute("ALTER TABLE qr_tokens ADD COLUMN operator TEXT DEFAULT ''")
        except Exception: pass
        for email, pw, name in SEED_ADMINS:
            if not c.execute("SELECT 1 FROM admins WHERE email=?", (email,)).fetchone():
                c.execute("INSERT INTO admins(email,name,pw) VALUES(?,?,?)",
                          (email, name, hash_pw(pw)))
        for k, v in DEFAULTS.items():
            if not c.execute("SELECT 1 FROM settings WHERE key=?", (k,)).fetchone():
                c.execute("INSERT INTO settings(key,value) VALUES(?,?)", (k, v))
        # Master (tool) password — stored hashed, default "vbs@123". Only vbs can change it.
        if not c.execute("SELECT 1 FROM settings WHERE key=?", ("master_pw_hash",)).fetchone():
            c.execute("INSERT INTO settings(key,value) VALUES(?,?)", ("master_pw_hash", hash_pw("vbs@123")))
        c.commit()


def get_setting(key, default=""):
    with db() as c:
        r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return r["value"] if r else default


def set_setting(key, value):
    with _db_lock, db() as c:
        c.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                  "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))
        c.commit()


# ── Tokens ────────────────────────────────────────────────────────────────────
def make_token(email: str) -> str:
    payload = base64.urlsafe_b64encode(json.dumps(
        {"e": email, "exp": int(time.time()) + TOKEN_TTL}).encode()).decode()
    sig = hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{payload}.{sig}"


def check_token(token: str) -> Optional[str]:
    try:
        payload, sig = token.split(".")
        if not hmac.compare_digest(sig, hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()[:32]):
            return None
        data = json.loads(base64.urlsafe_b64decode(payload))
        if data["exp"] < time.time():
            return None
        return data["e"]
    except Exception:
        return None


def require_admin(authorization: Optional[str]) -> str:
    token = (authorization or "").replace("Bearer ", "").strip()
    email = check_token(token)
    if not email:
        raise HTTPException(401, "Unauthorized")
    return email


def require_master(authorization: Optional[str]) -> str:
    """Only the MASTER admin (vbs) may pass. Used for master-password / grace control."""
    email = require_admin(authorization)
    if email.strip().lower() != MASTER_EMAIL.lower():
        raise HTTPException(403, "Master only")
    return email


# ── WebSocket hub ─────────────────────────────────────────────────────────────
class Hub:
    def __init__(self):
        self.tools: dict[str, WebSocket] = {}
        self.admins: list[WebSocket] = []

    async def push_tools(self, msg: dict):
        dead = []
        for eid, ws in list(self.tools.items()):
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(eid)
        for eid in dead:
            self.tools.pop(eid, None)

    async def push_admins(self, msg: dict):
        dead = []
        for ws in list(self.admins):
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in self.admins:
                self.admins.remove(ws)


hub = Hub()

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="LensIQ Management Server")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
init_db()


@app.get("/api/health")
def health():
    return {"ok": True, "service": "lensiq-mgmt", "version": get_setting("latest_version")}


# ── Admin auth ────────────────────────────────────────────────────────────────
@app.post("/api/admin/login")
async def admin_login(req: Request):
    body = await req.json()
    email = (body.get("email") or "").strip().lower()
    pw = body.get("password") or ""
    with db() as c:
        r = c.execute("SELECT * FROM admins WHERE email=?", (email,)).fetchone()
    if not r or not verify_pw(pw, r["pw"]):
        raise HTTPException(401, "Invalid credentials")
    return {"ok": True, "token": make_token(email), "name": r["name"], "email": email}


@app.get("/api/admin/me")
def admin_me(authorization: Optional[str] = Header(None)):
    return {"ok": True, "email": require_admin(authorization)}


@app.post("/api/admin/change_password")
async def admin_change_password(req: Request, authorization: Optional[str] = Header(None)):
    email = require_admin(authorization)
    body = await req.json()
    new = body.get("new_password") or ""
    if len(new) < 4:
        raise HTTPException(400, "Password too short")
    with _db_lock, db() as c:
        c.execute("UPDATE admins SET pw=? WHERE email=?", (hash_pw(new), email))
        c.commit()
    return {"ok": True}


# ── Employees ─────────────────────────────────────────────────────────────────
@app.get("/api/employees")
def list_employees(authorization: Optional[str] = Header(None)):
    require_admin(authorization)
    with db() as c:
        rows = c.execute("SELECT * FROM employees ORDER BY created_at DESC").fetchall()
    return {"ok": True, "employees": [dict(r) for r in rows]}


@app.post("/api/employees")
async def add_employee(req: Request, authorization: Optional[str] = Header(None)):
    require_admin(authorization)
    b = await req.json()
    eid = (b.get("employee_id") or "").strip()
    if not eid:
        raise HTTPException(400, "employee_id required")
    with _db_lock, db() as c:
        try:
            c.execute("INSERT INTO employees(employee_id,name,active,api_key_override,api_key2_override,model_override,google_sheets_url,created_at) "
                      "VALUES(?,?,?,?,?,?,?,?)",
                      (eid, b.get("name", ""), 1 if b.get("active", True) else 0,
                       b.get("api_key_override", ""), b.get("api_key2_override", ""),
                       b.get("model_override", ""), b.get("google_sheets_url", ""), int(time.time())))
            c.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(409, "employee_id already exists")
    return {"ok": True}


@app.patch("/api/employees/{eid}")
async def update_employee(eid: str, req: Request, authorization: Optional[str] = Header(None)):
    require_admin(authorization)
    b = await req.json()
    fields, vals = [], []
    for k in ("name", "active", "api_key_override", "api_key2_override", "model_override", "google_sheets_url"):
        if k in b:
            fields.append(f"{k}=?")
            vals.append(int(b[k]) if k == "active" else b[k])
    if not fields:
        return {"ok": True}
    vals.append(eid)
    with _db_lock, db() as c:
        c.execute(f"UPDATE employees SET {','.join(fields)} WHERE employee_id=?", vals)
        c.commit()
    await hub.push_tools({"type": "config_changed"})  # tools refetch config
    return {"ok": True}


@app.delete("/api/employees/{eid}")
def delete_employee(eid: str, authorization: Optional[str] = Header(None)):
    require_admin(authorization)
    with _db_lock, db() as c:
        c.execute("DELETE FROM employees WHERE employee_id=?", (eid,))
        c.commit()
    return {"ok": True}


# ── Employee gate (called by the tool at startup) ─────────────────────────────
@app.post("/api/employee/verify")
async def employee_verify(req: Request):
    b = await req.json()
    eid = (b.get("employee_id") or "").strip()
    if not eid:
        raise HTTPException(400, "employee_id required")
    with _db_lock, db() as c:
        r = c.execute("SELECT * FROM employees WHERE employee_id=?", (eid,)).fetchone()
        if r:
            c.execute("UPDATE employees SET last_seen=? WHERE employee_id=?", (int(time.time()), eid))
            c.commit()
    if not r:
        # TESTING PHASE: auto-register AND enable new employees so anyone can start.
        # (Later, flip active to 0 here to require admin approval before use.)
        with _db_lock, db() as c:
            c.execute("INSERT OR IGNORE INTO employees(employee_id,name,active,created_at,last_seen) "
                      "VALUES(?,?,?,?,?)", (eid, "", 1, int(time.time()), int(time.time())))
            c.commit()
        return {"ok": True, "name": "", "active": True}
    if not r["active"]:
        return {"ok": False, "reason": "inactive", "active": False}
    return {"ok": True, "name": r["name"], "active": True, "is_master": eid.strip().lower() == MASTER_EMAIL.lower()}


# ── Master control (vbs only): set the tool master password + offline grace ───
@app.get("/api/master/state")
def master_state(authorization: Optional[str] = Header(None)):
    """Tells the dashboard whether the logged-in admin is the master (to show the section)."""
    email = require_admin(authorization)
    is_master = email.strip().lower() == MASTER_EMAIL.lower()
    return {"ok": True, "is_master": is_master,
            "offline_grace_hours": int(get_setting("offline_grace_hours") or "24")}


@app.post("/api/master/verify")
async def master_verify(req: Request):
    """Tool calls this to validate an entered master password (online path)."""
    b = await req.json()
    pw = b.get("password") or ""
    stored = get_setting("master_pw_hash")
    return {"ok": bool(stored) and verify_pw(pw, stored)}


@app.post("/api/master/set_password")
async def master_set_password(req: Request, authorization: Optional[str] = Header(None)):
    require_master(authorization)
    b = await req.json()
    new = (b.get("new_password") or "").strip()
    if len(new) < 4:
        raise HTTPException(400, "Master password too short")
    set_setting("master_pw_hash", hash_pw(new))
    await hub.push_tools({"type": "config_changed"})
    return {"ok": True}


@app.post("/api/master/set_grace")
async def master_set_grace(req: Request, authorization: Optional[str] = Header(None)):
    require_master(authorization)
    b = await req.json()
    try:
        h = int(b.get("hours"))
    except (TypeError, ValueError):
        raise HTTPException(400, "hours must be an integer")
    if not (0 <= h <= 8760):
        raise HTTPException(400, "hours out of range")
    set_setting("offline_grace_hours", str(h))
    await hub.push_tools({"type": "config_changed"})
    return {"ok": True}


# ── Config sync (tool pulls everything it needs) ──────────────────────────────
@app.get("/api/config")
def get_config(employee_id: Optional[str] = None):
    api_key = get_setting("default_api_key")
    api_key_2 = get_setting("default_api_key_2")
    model = get_setting("default_model")
    fb1 = get_setting("default_fb1")
    fb2 = get_setting("default_fb2")
    google_sheets_url = get_setting("google_sheets_url")
    google_sheets_apps_script_url = get_setting("google_sheets_apps_script_url")
    if employee_id:
        with db() as c:
            r = c.execute("SELECT * FROM employees WHERE employee_id=?", (employee_id,)).fetchone()
        if r:
            api_key = r["api_key_override"] or api_key
            api_key_2 = (r["api_key2_override"] if "api_key2_override" in r.keys() else "") or api_key_2
            model = r["model_override"] or model
            google_sheets_url = (r["google_sheets_url"] if "google_sheets_url" in r.keys() else "") or google_sheets_url
    return {
        "ok": True,
        "tool_admin_password": get_setting("tool_admin_password"),
        "gemini_api_key": api_key,
        "gemini_api_key_2": api_key_2,
        "model": model, "fb1": fb1, "fb2": fb2,
        "google_sheets_url": google_sheets_url,
        "google_sheets_apps_script_url": google_sheets_apps_script_url,
        "flag_uncertain": get_setting("flag_uncertain") == "1",
        "flag_threshold": int(get_setting("flag_threshold") or "90"),
        "dedup_enabled": get_setting("dedup_enabled") == "1",
        "master_pw_hash": get_setting("master_pw_hash"),     # tool caches this (one-way) for offline master unlock
        "offline_grace_hours": int(get_setting("offline_grace_hours") or "24"),
        "latest_version": get_setting("latest_version"),
        "update_pushed": get_setting("update_pushed") == "1",
        "update_filename": get_setting("update_filename"),
        "update_notes": get_setting("update_notes"),
        "broadcast": {
            "id": get_setting("broadcast_id"),
            "message": get_setting("broadcast_message"),
            "level": get_setting("broadcast_level"),
        },
    }


# ── Usage telemetry (tool pushes; supports offline batch flush) ───────────────
@app.post("/api/usage")
async def post_usage(req: Request):
    b = await req.json()
    events = b.get("events") or [b]   # accept single or batched
    with _db_lock, db() as c:
        for e in events:
            c.execute("INSERT INTO usage(employee_id,ts,engine,images,records,ocr_ms,classify_ms,session_duration,manual_corrections,offline_images) "
                      "VALUES(?,?,?,?,?,?,?,?,?,?)",
                      (e.get("employee_id", ""), int(e.get("ts", time.time())), e.get("engine", ""),
                       int(e.get("images", 0)), int(e.get("records", 0)),
                       float(e.get("ocr_ms", 0)), float(e.get("classify_ms", 0)),
                       int(e.get("session_duration", 0)), int(e.get("manual_corrections", 0)),
                       int(e.get("offline_images", 0))))
        c.commit()
    await hub.push_admins({"type": "usage", "count": len(events)})
    return {"ok": True, "stored": len(events)}


@app.get("/api/usage/summary")
def usage_summary(authorization: Optional[str] = Header(None)):
    require_admin(authorization)
    with db() as c:
        rows = c.execute("""
            SELECT e.employee_id, e.name, e.active, e.last_seen,
                   COALESCE(SUM(u.images),0) AS images,
                   COALESCE(SUM(u.records),0) AS records,
                   COUNT(u.id) AS requests
            FROM employees e LEFT JOIN usage u ON u.employee_id = e.employee_id
            GROUP BY e.employee_id ORDER BY images DESC
        """).fetchall()
    return {"ok": True, "summary": [dict(r) for r in rows]}


@app.get("/api/usage/recent")
def usage_recent(limit: int = 100, authorization: Optional[str] = Header(None)):
    require_admin(authorization)
    with db() as c:
        rows = c.execute("SELECT * FROM usage ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    return {"ok": True, "events": [dict(r) for r in rows]}


# ── Settings (admin) ──────────────────────────────────────────────────────────
@app.get("/api/settings")
def read_settings(authorization: Optional[str] = Header(None)):
    require_admin(authorization)
    keys = ["tool_admin_password", "default_api_key", "default_api_key_2", "default_model", "default_fb1", "default_fb2", "google_sheets_url", "google_sheets_apps_script_url", "flag_uncertain", "flag_threshold", "dedup_enabled"]
    return {"ok": True, "settings": {k: get_setting(k) for k in keys}}


@app.post("/api/settings")
async def write_settings(req: Request, authorization: Optional[str] = Header(None)):
    require_admin(authorization)
    b = await req.json()
    for k in ["tool_admin_password", "default_api_key", "default_api_key_2", "default_model", "default_fb1", "default_fb2", "google_sheets_url", "google_sheets_apps_script_url"]:
        if k in b:
            set_setting(k, b[k])
    # Uncertainty flagging — normalise bool/number to the stored string form.
    if "flag_uncertain" in b:
        set_setting("flag_uncertain", "1" if b["flag_uncertain"] in (True, 1, "1", "true", "True") else "0")
    if "dedup_enabled" in b:
        set_setting("dedup_enabled", "1" if b["dedup_enabled"] in (True, 1, "1", "true", "True") else "0")
    if "flag_threshold" in b:
        try:
            t = int(b["flag_threshold"])
            if 0 <= t <= 100:
                set_setting("flag_threshold", str(t))
        except (TypeError, ValueError):
            pass
    await hub.push_tools({"type": "config_changed"})
    return {"ok": True}


# ── Broadcast ─────────────────────────────────────────────────────────────────
@app.post("/api/broadcast")
async def broadcast(req: Request, authorization: Optional[str] = Header(None)):
    require_admin(authorization)
    b = await req.json()
    msg = b.get("message", "")
    level = b.get("level", "info")
    bid = str(int(get_setting("broadcast_id", "0")) + 1)
    set_setting("broadcast_message", msg)
    set_setting("broadcast_level", level)
    set_setting("broadcast_id", bid)
    await hub.push_tools({"type": "broadcast", "id": bid, "message": msg, "level": level})
    return {"ok": True, "id": bid}

@app.delete("/api/broadcast")
async def clear_broadcast(authorization: Optional[str] = Header(None)):
    require_admin(authorization)
    bid = str(int(get_setting("broadcast_id", "0")) + 1)
    set_setting("broadcast_message", "")
    set_setting("broadcast_level", "info")
    set_setting("broadcast_id", bid)
    await hub.push_tools({"type": "broadcast", "id": bid, "message": "", "level": "info"})
    return {"ok": True, "id": bid}


# ── Updates ───────────────────────────────────────────────────────────────────
@app.post("/api/updates/upload")
async def upload_update(version: str = Form(...), notes: str = Form(""),
                        file: UploadFile = File(...),
                        authorization: Optional[str] = Header(None)):
    require_admin(authorization)
    safe = os.path.basename(file.filename)
    dest = os.path.join(UPLOAD_DIR, safe)
    with open(dest, "wb") as f:
        while chunk := await file.read(1 << 20):
            f.write(chunk)
    size = os.path.getsize(dest)
    set_setting("latest_version", version)
    set_setting("update_filename", safe)
    set_setting("update_notes", notes)
    set_setting("update_pushed", "0")
    with _db_lock, db() as c:
        c.execute("INSERT INTO update_history(version,filename,notes,size,uploaded_at,pushed) VALUES(?,?,?,?,?,0)",
                  (version, safe, notes, size, int(time.time())))
        c.commit()
    return {"ok": True, "filename": safe, "version": version, "size": size}


@app.post("/api/updates/push")
async def push_update(authorization: Optional[str] = Header(None)):
    require_admin(authorization)
    set_setting("update_pushed", "1")
    with _db_lock, db() as c:
        c.execute("UPDATE update_history SET pushed=1 WHERE filename=?", (get_setting("update_filename"),))
        c.commit()
    await hub.push_tools({"type": "update_available", "version": get_setting("latest_version"),
                          "notes": get_setting("update_notes")})
    return {"ok": True}


@app.get("/api/updates/history")
def update_history(authorization: Optional[str] = Header(None)):
    require_admin(authorization)
    with db() as c:
        rows = c.execute("SELECT * FROM update_history ORDER BY uploaded_at DESC").fetchall()
    return {"ok": True, "history": [dict(r) for r in rows]}


@app.patch("/api/updates/notes/{version}")
async def update_notes(version: str, req: Request, authorization: Optional[str] = Header(None)):
    require_admin(authorization)
    b = await req.json()
    notes = b.get("notes", "")
    with _db_lock, db() as c:
        c.execute("UPDATE update_history SET notes=? WHERE version=?", (notes, version))
        c.commit()
    # If editing the current latest version, update the global setting
    if get_setting("latest_version") == version:
        set_setting("update_notes", notes)
    return {"ok": True}


@app.post("/api/updates/clear")
def clear_updates(authorization: Optional[str] = Header(None)):
    require_admin(authorization)
    with db() as c:
        rows = c.execute("SELECT filename FROM update_history").fetchall()
    for r in rows:
        try:
            p = os.path.join(UPLOAD_DIR, os.path.basename(r["filename"]))
            if os.path.exists(p):
                os.remove(p)
        except Exception:
            pass
    with _db_lock, db() as c:
        c.execute("DELETE FROM update_history")
        c.commit()
    set_setting("update_pushed", "0")
    set_setting("update_filename", "")
    set_setting("update_notes", "")
    return {"ok": True}


@app.get("/api/updates/latest")
def latest_update():
    return {"ok": True, "version": get_setting("latest_version"),
            "pushed": get_setting("update_pushed") == "1",
            "filename": get_setting("update_filename"),
            "notes": get_setting("update_notes")}


@app.get("/api/updates/download/{filename}")
def download_update(filename: str):
    path = os.path.join(UPLOAD_DIR, os.path.basename(filename))
    if not os.path.exists(path):
        raise HTTPException(404, "Not found")
    return FileResponse(path, filename=filename, media_type="application/octet-stream")


# ── QR admin login ────────────────────────────────────────────────────────────
def _qr_requires_master(qr) -> bool:
    """True if the tool that created this QR is running as the master operator (vbs).
    Such a QR may ONLY be approved by the master admin."""
    try:
        op = (qr["operator"] if "operator" in qr.keys() else "") or ""
    except Exception:
        op = ""
    return op.strip().lower() == MASTER_EMAIL.lower()


@app.post("/api/qr/create")
async def qr_create(req: Request):
    # The tool passes its current operator employee_id so the server can enforce
    # that a vbs-operator tool is only unlocked by the master admin.
    operator = ""
    try:
        b = await req.json()
        operator = (b.get("operator") or "").strip()
    except Exception:
        pass
    token = secrets.token_urlsafe(18)
    with _db_lock, db() as c:
        c.execute("INSERT INTO qr_tokens(token,created,status,operator) VALUES(?,?,?,?)",
                  (token, int(time.time()), "pending", operator))
        c.commit()
    return {"ok": True, "token": token}


@app.get("/api/qr/status/{token}")
def qr_status(token: str):
    with db() as c:
        r = c.execute("SELECT * FROM qr_tokens WHERE token=?", (token,)).fetchone()
    if not r:
        return {"ok": False, "status": "invalid"}
    if r["created"] < time.time() - 300:
        return {"ok": False, "status": "expired"}
    return {"ok": True, "status": r["status"],
            "auth_token": r["auth_token"] if r["status"] == "approved" else None,
            "email": r["admin_email"]}


@app.post("/api/qr/approve")
async def qr_approve(req: Request, authorization: Optional[str] = Header(None)):
    # Approve a tool QR using an ALREADY-logged-in dashboard session (no re-login).
    email = require_admin(authorization)
    b = await req.json()
    token = (b.get("token") or "").strip()
    if "qr=" in token:                      # tolerate scanning the full URL
        token = token.split("qr=")[-1].split("&")[0]
    with db() as c:
        qr = c.execute("SELECT * FROM qr_tokens WHERE token=?", (token,)).fetchone()
    if not qr or qr["created"] < time.time() - 300:
        raise HTTPException(400, "QR expired or invalid")
    if _qr_requires_master(qr) and email.strip().lower() != MASTER_EMAIL.lower():
        raise HTTPException(403, "Only the master (vbs) can unlock a vbs-operator tool")
    auth = make_token(email)
    with _db_lock, db() as c:
        c.execute("UPDATE qr_tokens SET status='approved', admin_email=?, auth_token=? WHERE token=?",
                  (email, auth, token))
        c.commit()
    return {"ok": True}


@app.post("/api/qr/scan")
async def qr_scan(req: Request):
    b = await req.json()
    token = b.get("token", "")
    email = (b.get("email") or "").strip().lower()
    pw = b.get("password") or ""
    with db() as c:
        admin = c.execute("SELECT * FROM admins WHERE email=?", (email,)).fetchone()
        qr = c.execute("SELECT * FROM qr_tokens WHERE token=?", (token,)).fetchone()
    if not qr or qr["created"] < time.time() - 300:
        raise HTTPException(400, "QR expired")
    if not admin or not verify_pw(pw, admin["pw"]):
        raise HTTPException(401, "Invalid credentials")
    if _qr_requires_master(qr) and email != MASTER_EMAIL.lower():
        raise HTTPException(403, "Only the master (vbs) can unlock a vbs-operator tool")
    auth = make_token(email)
    with _db_lock, db() as c:
        c.execute("UPDATE qr_tokens SET status='approved', admin_email=?, auth_token=? WHERE token=?",
                  (email, auth, token))
        c.commit()
    return {"ok": True}


# ── WebSocket endpoints ───────────────────────────────────────────────────────
@app.websocket("/ws/tool/{employee_id}")
async def ws_tool(ws: WebSocket, employee_id: str):
    await ws.accept()
    hub.tools[employee_id] = ws
    try:
        await ws.send_json({"type": "connected"})
        while True:
            await ws.receive_text()  # keepalive / ignore
    except WebSocketDisconnect:
        hub.tools.pop(employee_id, None)
    except Exception:
        hub.tools.pop(employee_id, None)


@app.websocket("/ws/admin")
async def ws_admin(ws: WebSocket):
    await ws.accept()
    hub.admins.append(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        if ws in hub.admins:
            hub.admins.remove(ws)
    except Exception:
        if ws in hub.admins:
            hub.admins.remove(ws)


if __name__ == "__main__":
    print(f"[lensiq-mgmt] starting on :{PORT}  db={DB_PATH}")
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")
