"""
AITRC Vita - Department HOD Grievance Portal
Flask + SQLite backend.

Run:   python app.py          (then open http://127.0.0.1:5000)
Tests: python -m unittest -v
"""
import csv
import hashlib
import hmac
import io
import os
import re
import secrets
import sqlite3
import sys
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

import click
from flask import Flask, Response, current_app, g, jsonify, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

# --------------------------------------------------------------------------
# Domain constants (single source of truth - the frontend loads them from the API)
# --------------------------------------------------------------------------
LEVELS = ("Degree", "Diploma")
DEPARTMENTS = (
    "Computer Science",
    "Artificial Intelligence and Machine Learning",
    "Civil Engineering",
    "Mechanical",
    "Electrical",
    "Electrical and Telecommunication",
    "Electrical and Computer",
)
YEARS = {
    "Degree": ("1st Year", "2nd Year", "3rd Year", "4th Year"),
    "Diploma": ("1st Year", "2nd Year", "3rd Year"),  # diploma has no 4th year
}
CATEGORIES = (
    "faculties",
    "teaching",
    "classroom issue",
    "attendance issue",
    "personal issue",
    "others",
)
CUSTOM_CATEGORIES = ("personal issue", "others")  # these need a short free-text title
STATUSES = ("Pending", "In Progress", "Resolved")

PRN_RE = re.compile(r"^[0-9]{6,15}$")
# 32 unambiguous characters (no 0/O/1/I) -> 12 chars = 60 bits of entropy
PIN_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
PIN_LEN = 12
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Tailwind's Play CDN needs 'unsafe-eval'. Remove it once you build Tailwind locally.
CSP = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.tailwindcss.com 'unsafe-eval'; "
    "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
    "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
    "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
    "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS students (
    prn           TEXT PRIMARY KEY,
    level         TEXT NOT NULL DEFAULT 'Degree' CHECK (level IN ('Degree','Diploma')),
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hods (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    level         TEXT NOT NULL CHECK (level IN ('Degree','Diploma')),
    dept          TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    registered    INTEGER NOT NULL DEFAULT 0,   -- 0 = HOD has not set a password yet
    updated_at    TEXT NOT NULL,
    UNIQUE (level, dept)
);
CREATE TABLE IF NOT EXISTS complaints (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    pin_hash     TEXT NOT NULL UNIQUE,            -- SHA-256 of the tracking code (never stored in clear)
    level        TEXT NOT NULL CHECK (level IN ('Degree','Diploma')),
    dept         TEXT NOT NULL,
    year         TEXT NOT NULL,
    category     TEXT NOT NULL,
    custom_text  TEXT,
    student_prn  TEXT,                            -- NULL when the complaint is anonymous
    student_name TEXT,                            -- NULL when the complaint is anonymous
    subject      TEXT NOT NULL,
    description  TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'Pending'
                 CHECK (status IN ('Pending','In Progress','Resolved')),
    remarks      TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_complaints_scope ON complaints (level, dept, status);
CREATE TABLE IF NOT EXISTS rate_events (
    key TEXT NOT NULL,
    ts  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_key ON rate_events (key, ts);
CREATE TABLE IF NOT EXISTS audit_log (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TEXT NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT
);
"""

# Used to make "unknown user" take as long as "wrong password" (no timing oracle).
_DUMMY_HASH = generate_password_hash("not-a-real-password", method="pbkdf2:sha256")


class ApiError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.message = message
        self.status = status


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ref_for(complaint_id):
    return f"AIT-{complaint_id:05d}"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"], timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def audit(actor, action, detail=""):
    get_db().execute(
        "INSERT INTO audit_log (ts, actor, action, detail) VALUES (?,?,?,?)",
        (now_iso(), actor, action, detail),
    )


def get_json():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError("Invalid request body.")
    return data


def clean_text(data, key, label, max_len, min_len=0, multiline=False, required=True):
    value = data.get(key)
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ApiError(f"{label} must be text.")
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    value = CONTROL_CHARS.sub("", value)
    value = value.strip() if multiline else " ".join(value.split())
    if not value:
        if required:
            raise ApiError(f"{label} is required.")
        return ""
    if len(value) < min_len:
        raise ApiError(f"{label} must be at least {min_len} characters.")
    if len(value) > max_len:
        raise ApiError(f"{label} must be at most {max_len} characters.")
    return value


def choice(data, key, label, allowed):
    value = data.get(key)
    if not isinstance(value, str) or value not in allowed:
        raise ApiError(f"Please select a valid {label}.")
    return value


def check_password_policy(password, label="Password"):
    if not isinstance(password, str) or not (8 <= len(password) <= 128):
        raise ApiError(f"{label} must be between 8 and 128 characters.")
    return password


def password_fingerprint(password_hash):
    """Stored in the session so changing a password logs out all other sessions."""
    return hashlib.sha256(password_hash.encode()).hexdigest()[:16]


def hash_password(password, method=None):
    method = method or current_app.config.get("PASSWORD_HASH_METHOD", "pbkdf2:sha256")
    return generate_password_hash(password, method=method)


def new_pin():
    return "".join(secrets.choice(PIN_ALPHABET) for _ in range(PIN_LEN))


def format_pin(pin):
    return "-".join(pin[i:i + 4] for i in range(0, len(pin), 4))


def normalize_pin(raw):
    if not isinstance(raw, str):
        return None
    pin = re.sub(r"[\s-]", "", raw).upper()
    if len(pin) != PIN_LEN or any(c not in PIN_ALPHABET for c in pin):
        return None
    return pin


def hash_pin(pin):
    return hashlib.sha256(pin.encode()).hexdigest()


def client_ip():
    # If you deploy behind a reverse proxy, configure it (and werkzeug's ProxyFix) so
    # remote_addr is the real client address.
    return request.remote_addr or "unknown"


# ---- rate limiting (stored in SQLite so it survives restarts / multiple workers)
def rate_limited(key, limit, window):
    if not current_app.config.get("RATE_LIMIT_ENABLED", True):
        return False
    db = get_db()
    now = time.time()
    db.execute("DELETE FROM rate_events WHERE ts < ?", (now - 86400,))
    count = db.execute(
        "SELECT COUNT(*) FROM rate_events WHERE key = ? AND ts > ?", (key, now - window)
    ).fetchone()[0]
    return count >= limit


def rate_record(key):
    get_db().execute("INSERT INTO rate_events (key, ts) VALUES (?, ?)", (key, time.time()))


def rate_clear(key):
    get_db().execute("DELETE FROM rate_events WHERE key = ?", (key,))


def too_many():
    return ApiError("Too many attempts. Please wait a few minutes and try again.", 429)


def csv_safe(value):
    """Neutralise spreadsheet formula injection (=, +, -, @ at start of a cell)."""
    if value is None:
        return ""
    text = str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def like_pattern(text):
    escaped = text.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


# --------------------------------------------------------------------------
# Authentication helpers
# --------------------------------------------------------------------------
def current_user():
    """Return the logged-in user dict (re-validated against the DB) or None."""
    role = session.get("role")
    db = get_db()
    if role == "student":
        row = db.execute(
            "SELECT prn, level, password_hash FROM students WHERE prn = ?", (session.get("prn"),)
        ).fetchone()
        if row and hmac.compare_digest(password_fingerprint(row["password_hash"]), session.get("fp", "")):
            return {"role": "student", "prn": row["prn"], "level": row["level"]}
    elif role == "hod":
        row = db.execute(
            "SELECT id, level, dept, password_hash, registered FROM hods WHERE id = ?", (session.get("hod_id"),)
        ).fetchone()
        if row and row["registered"] and hmac.compare_digest(password_fingerprint(row["password_hash"]), session.get("fp", "")):
            return {"role": "hod", "id": row["id"], "level": row["level"], "dept": row["dept"]}
    return None


def require_role(role):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                session.pop("role", None)
                raise ApiError("Please log in to continue.", 401)
            if user["role"] != role:
                raise ApiError("You do not have permission to do that.", 403)
            g.user = user
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def start_session(role, fp, **ids):
    csrf = secrets.token_urlsafe(32)
    session.clear()  # prevents session fixation
    session.permanent = True
    session["role"] = role
    session["fp"] = fp
    session["csrf"] = csrf
    for k, v in ids.items():
        session[k] = v
    return csrf


def ensure_csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


# --------------------------------------------------------------------------
# Database setup
# --------------------------------------------------------------------------
def init_db(app):
    """Create tables and one *unregistered* HOD slot per (level, department).

    HODs choose their own password through the Register screen (protected by the
    HOD setup code), so no passwords are generated or handed around any more.
    """
    conn = sqlite3.connect(app.config["DATABASE"])
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA)
        # Backward-compatible migration for databases created before student study level existed.
        student_cols = [r[1] for r in conn.execute("PRAGMA table_info(students)")]
        if "level" not in student_cols:
            # Existing student accounts are kept and assigned Degree as a safe default.
            conn.execute("ALTER TABLE students ADD COLUMN level TEXT NOT NULL DEFAULT 'Degree'")
        # Migrate databases created by the old version (random, unknown HOD passwords).
        cols = [r[1] for r in conn.execute("PRAGMA table_info(hods)")]
        if "registered" not in cols:
            conn.execute("ALTER TABLE hods ADD COLUMN registered INTEGER NOT NULL DEFAULT 1")
            # Accounts whose password was never changed still have the unknown random one -> let them register.
            conn.execute(
                "UPDATE hods SET registered = 0 WHERE NOT EXISTS ("
                " SELECT 1 FROM audit_log a WHERE a.action = 'change_password'"
                " AND a.actor = 'hod:' || hods.level || '/' || hods.dept)"
            )
        for level in LEVELS:
            for dept in DEPARTMENTS:
                # Placeholder hash of a random secret nobody knows: the slot cannot be logged into
                # until the HOD registers.
                conn.execute(
                    "INSERT OR IGNORE INTO hods (level, dept, password_hash, registered, updated_at) VALUES (?,?,?,0,?)",
                    (level, dept, generate_password_hash(secrets.token_urlsafe(32),
                                                         method=app.config.get("PASSWORD_HASH_METHOD", "pbkdf2:sha256")),
                     now_iso()),
                )
        conn.commit()
    finally:
        conn.close()


def load_hod_setup_code(app):
    """Code the college gives to HODs so only they can register an HOD account."""
    code = app.config.get("HOD_SETUP_CODE") or os.environ.get("AITRC_HOD_SETUP_CODE")
    if code:
        return code, None
    path = Path(app.instance_path) / "hod_setup_code.txt"
    if path.exists():
        return path.read_text().strip(), path
    code = secrets.token_urlsafe(8)
    path.write_text(code + "\n")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    print(f"\n* HOD setup code (give it only to HODs for registration):\n  {code}\n  saved in {path}\n", file=sys.stderr)
    return code, path


def load_secret_key(instance_path):
    env_key = os.environ.get("AITRC_SECRET_KEY")
    if env_key:
        return env_key
    path = Path(instance_path) / "secret_key"
    if path.exists():
        return path.read_text().strip()
    key = secrets.token_hex(32)
    path.write_text(key)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return key


# --------------------------------------------------------------------------
# App factory
# --------------------------------------------------------------------------
def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    app.config.update(
        DATABASE=str(Path(app.instance_path) / "aitrc.db"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("AITRC_HTTPS") == "1",
        PERMANENT_SESSION_LIFETIME=2 * 60 * 60,  # 2 hours
        MAX_CONTENT_LENGTH=32 * 1024,
        RATE_LIMIT_ENABLED=True,
        HOD_SETUP_CODE_REQUIRED=os.environ.get("AITRC_HOD_SETUP_CODE_REQUIRED", "1") != "0",  # set env to 0 to let HODs register without a code (less secure)
        HOD_SETUP_CODE=None,   # or set env AITRC_HOD_SETUP_CODE; otherwise generated into instance/hod_setup_code.txt
        PASSWORD_HASH_METHOD="pbkdf2:sha256",  # 600k iterations by default in Werkzeug 3
    )
    if test_config:
        app.config.update(test_config)
    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = load_secret_key(app.instance_path)

    init_db(app)
    if app.config["HOD_SETUP_CODE_REQUIRED"]:
        app.config["HOD_SETUP_CODE_VALUE"], _ = load_hod_setup_code(app)
    else:
        app.config["HOD_SETUP_CODE_VALUE"] = None
        print("\n* WARNING: HOD setup code is switched off - anyone who reaches the site can register an unregistered HOD account.\n", file=sys.stderr)

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.before_request
    def csrf_and_content_type():
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.path.startswith("/api/"):
            if not request.is_json:
                raise ApiError("Content-Type must be application/json.", 415)
            sent = request.headers.get("X-CSRF-Token", "")
            expected = session.get("csrf", "")
            if not expected or not hmac.compare_digest(sent.encode("utf-8", "replace"), expected.encode()):
                raise ApiError("Security token missing or expired. Please refresh the page.", 403)

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.errorhandler(ApiError)
    def handle_api_error(err):
        return jsonify(error=err.message), err.status

    @app.errorhandler(404)
    def handle_404(_e):
        return jsonify(error="Not found."), 404

    @app.errorhandler(405)
    def handle_405(_e):
        return jsonify(error="Method not allowed."), 405

    @app.errorhandler(413)
    def handle_413(_e):
        return jsonify(error="Request too large."), 413

    @app.errorhandler(Exception)
    def handle_unexpected(err):
        from werkzeug.exceptions import HTTPException
        if isinstance(err, HTTPException):
            return jsonify(error=err.description), err.code
        app.logger.exception("Unhandled error")
        return jsonify(error="Something went wrong on the server."), 500

    register_routes(app)
    register_cli(app)
    return app


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
def register_routes(app):
    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/session")
    def api_session():
        user = current_user()
        payload = {
            "csrf": ensure_csrf(),
            "user": None,
            "meta": {
                "levels": LEVELS,
                "departments": DEPARTMENTS,
                "years": YEARS,
                "categories": CATEGORIES,
                "customCategories": CUSTOM_CATEGORIES,
                "statuses": STATUSES,
                "hodCodeRequired": bool(current_app.config["HOD_SETUP_CODE_REQUIRED"]),
            },
        }
        if user:
            payload["user"] = {k: v for k, v in user.items() if k != "id"}
        return jsonify(payload)

    # ---- accounts -------------------------------------------------------
    @app.post("/api/register")
    def register():
        data = get_json()
        ip = client_ip()
        prn = data.get("prn")
        if not isinstance(prn, str) or not PRN_RE.match(prn.strip()):
            raise ApiError("PRN must be 6 to 15 digits.")
        prn = prn.strip()
        level = choice(data, "level", "study level", LEVELS) if "level" in data else "Degree"
        password = check_password_policy(data.get("password"))
        confirm = data.get("confirm_password")
        if not isinstance(confirm, str) or not hmac.compare_digest(password, confirm):
            raise ApiError("Passwords do not match.")
        if rate_limited(f"register:{ip}", 10, 3600):
            raise too_many()
        rate_record(f"register:{ip}")
        pw_hash = hash_password(password)
        db = get_db()
        db.commit()
        try:
            db.execute(
                "INSERT INTO students (prn, level, password_hash, created_at) VALUES (?,?,?,?)",
                (prn, level, pw_hash, now_iso()),
            )
        except sqlite3.IntegrityError:
            db.rollback()
            raise ApiError("This PRN is already registered. Please log in instead.", 409)
        db.commit()
        csrf = start_session("student", password_fingerprint(pw_hash), prn=prn)
        return jsonify(csrf=csrf, user={"role": "student", "prn": prn, "level": level}), 201

    @app.post("/api/register-hod")
    def register_hod():
        """First-time HOD registration: the HOD chooses their own password (needs the HOD setup code)."""
        data = get_json()
        ip = client_ip()
        level = choice(data, "level", "study level", LEVELS)
        dept = choice(data, "dept", "department", DEPARTMENTS)
        password = check_password_policy(data.get("password"))
        confirm = data.get("confirm_password")
        if not isinstance(confirm, str) or not hmac.compare_digest(password, confirm):
            raise ApiError("Passwords do not match.")
        code_required = current_app.config["HOD_SETUP_CODE_REQUIRED"]
        code = data.get("setup_code")
        if code_required and (not isinstance(code, str) or not code.strip() or len(code) > 128):
            raise ApiError("Please enter the HOD setup code.")

        key = f"hodreg:{level}|{dept}:{ip}"
        ip_key = f"hodreg-ip:{ip}"
        if rate_limited(key, 5, 900) or rate_limited(ip_key, 20, 900):
            raise too_many()

        db = get_db()
        row = db.execute("SELECT id, registered FROM hods WHERE level = ? AND dept = ?", (level, dept)).fetchone()
        if code_required and not hmac.compare_digest(code.strip().encode(), current_app.config["HOD_SETUP_CODE_VALUE"].encode()):
            rate_record(key)
            rate_record(ip_key)
            db.commit()
            raise ApiError("Invalid HOD setup code.", 403)
        if row is None:
            raise ApiError("HOD account not found.", 404)
        if row["registered"]:
            raise ApiError("This HOD account is already registered. Please log in instead.", 409)

        pw_hash = hash_password(password)
        cur = db.execute(
            "UPDATE hods SET password_hash = ?, registered = 1, updated_at = ? WHERE id = ? AND registered = 0",
            (pw_hash, now_iso(), row["id"]),
        )
        if cur.rowcount != 1:
            db.rollback()
            raise ApiError("This HOD account is already registered. Please log in instead.", 409)
        audit(f"hod:{level}/{dept}", "register")
        rate_clear(key)
        db.commit()
        csrf = start_session("hod", password_fingerprint(pw_hash), hod_id=row["id"])
        return jsonify(csrf=csrf, user={"role": "hod", "level": level, "dept": dept}), 201

    @app.post("/api/login")
    def login():
        data = get_json()
        role = data.get("role")
        password = data.get("password")
        ip = client_ip()
        if role not in ("student", "hod") or not isinstance(password, str) or len(password) > 128:
            raise ApiError("Invalid credentials.", 401)

        if role == "student":
            prn = data.get("prn")
            prn = prn.strip() if isinstance(prn, str) else ""
            level = choice(data, "level", "study level", LEVELS) if "level" in data else "Degree"
            identity = f"{level}|{prn[:20]}"
        else:
            level = choice(data, "level", "study level", LEVELS)
            dept = choice(data, "dept", "department", DEPARTMENTS)
            identity = f"{level}|{dept}"

        key = f"login:{role}:{identity}:{ip}"
        ip_key = f"login-ip:{ip}"
        if rate_limited(key, 5, 900) or rate_limited(ip_key, 30, 900):
            raise too_many()

        db = get_db()
        if role == "student":
            row = db.execute("SELECT prn, level, password_hash FROM students WHERE prn = ? AND level = ?", (prn, level)).fetchone()
        else:
            row = db.execute(
                "SELECT id, level, dept, password_hash, registered FROM hods WHERE level = ? AND dept = ?",
                (level, dept),
            ).fetchone()
        if role == "hod" and row is not None and not row["registered"]:
            raise ApiError("This HOD account is not registered yet. Please click 'New HOD? Register' first.", 403)
        ok = check_password_hash(row["password_hash"] if row else _DUMMY_HASH, password) and row is not None
        if not ok:
            rate_record(key)
            rate_record(ip_key)
            db.commit()
            raise ApiError("Invalid credentials.", 401)

        rate_clear(key)
        if role == "student":
            csrf = start_session("student", password_fingerprint(row["password_hash"]), prn=row["prn"])
            user = {"role": "student", "prn": row["prn"], "level": row["level"]}
        else:
            csrf = start_session("hod", password_fingerprint(row["password_hash"]), hod_id=row["id"])
            user = {"role": "hod", "level": row["level"], "dept": row["dept"]}
            audit(f"hod:{row['level']}/{row['dept']}", "login")
        db.commit()
        return jsonify(csrf=csrf, user=user)

    @app.post("/api/logout")
    def logout():
        session.clear()
        return jsonify(csrf=ensure_csrf(), ok=True)

    @app.post("/api/change-password")
    def change_password():
        data = get_json()
        role = data.get("role")
        old_password = data.get("old_password")
        new_password = check_password_policy(data.get("new_password"), "New password")
        ip = client_ip()
        if role not in ("student", "hod") or not isinstance(old_password, str) or len(old_password) > 128:
            raise ApiError("Invalid request.")
        if old_password == new_password:
            raise ApiError("New password must be different from the current one.")

        db = get_db()
        if role == "student":
            prn = data.get("prn")
            prn = prn.strip() if isinstance(prn, str) else ""
            identity = prn[:20]
            row = db.execute("SELECT prn, password_hash FROM students WHERE prn = ?", (prn,)).fetchone()
        else:
            level = choice(data, "level", "study level", LEVELS)
            dept = choice(data, "dept", "department", DEPARTMENTS)
            identity = f"{level}|{dept}"
            row = db.execute(
                "SELECT id, level, dept, password_hash, registered FROM hods WHERE level = ? AND dept = ?",
                (level, dept),
            ).fetchone()

        key = f"login:{role}:{identity}:{ip}"  # shares the login lockout counter
        if rate_limited(key, 5, 900):
            raise too_many()
        if role == "hod" and row is not None and not row["registered"]:
            raise ApiError("This HOD account is not registered yet. Please register first.", 403)
        if not (check_password_hash(row["password_hash"] if row else _DUMMY_HASH, old_password) and row):
            rate_record(key)
            db.commit()
            raise ApiError("Current password is incorrect.", 401)

        new_hash = hash_password(new_password)
        if role == "student":
            db.execute("UPDATE students SET password_hash = ? WHERE prn = ?", (new_hash, row["prn"]))
            actor = f"student:{row['prn']}"
            same_user = session.get("role") == "student" and session.get("prn") == row["prn"]
        else:
            db.execute(
                "UPDATE hods SET password_hash = ?, updated_at = ? WHERE id = ?",
                (new_hash, now_iso(), row["id"]),
            )
            actor = f"hod:{row['level']}/{row['dept']}"
            same_user = session.get("role") == "hod" and session.get("hod_id") == row["id"]
        audit(actor, "change_password")
        rate_clear(key)
        db.commit()
        if same_user:  # keep this session alive, all others are invalidated
            session["fp"] = password_fingerprint(new_hash)
        return jsonify(ok=True)

    # ---- student: submit + track ---------------------------------------
    @app.post("/api/complaints")
    @require_role("student")
    def submit_complaint():
        data = get_json()
        level = choice(data, "level", "study level", LEVELS)
        if level != g.user["level"]:
            raise ApiError("The selected study level does not match your student account.", 403)
        dept = choice(data, "dept", "department", DEPARTMENTS)
        year = choice(data, "year", "year of study", YEARS[level])
        category = choice(data, "category", "category", CATEGORIES)
        custom = None
        if category in CUSTOM_CATEGORIES:
            custom = clean_text(data, "custom_text", "Issue title", 150, min_len=3)
        name = clean_text(data, "name", "Name", 80, required=False)
        subject = clean_text(data, "subject", "Subject", 150, min_len=3)
        description = clean_text(data, "description", "Description", 3000, min_len=10, multiline=True)

        ip = client_ip()
        if rate_limited(f"submit:{ip}", 10, 3600):
            raise too_many()
        rate_record(f"submit:{ip}")

        # Blank name => genuinely anonymous: the PRN is NOT stored with the complaint.
        prn = g.user["prn"] if name else None
        stamp = now_iso()
        db = get_db()
        for _ in range(5):
            pin = new_pin()
            try:
                cur = db.execute(
                    """INSERT INTO complaints
                       (pin_hash, level, dept, year, category, custom_text, student_prn, student_name,
                        subject, description, status, remarks, created_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?, 'Pending', '', ?, ?)""",
                    (hash_pin(pin), level, dept, year, category, custom, prn, name or None,
                     subject, description, stamp, stamp),
                )
                break
            except sqlite3.IntegrityError:
                db.rollback()
        else:
            raise ApiError("Could not create the complaint. Please try again.", 500)
        db.commit()
        return jsonify(ref=ref_for(cur.lastrowid), pin=format_pin(pin), anonymous=not name), 201

    @app.post("/api/track")
    @require_role("student")
    def track_complaint():
        data = get_json()
        ip = client_ip()
        key = f"track:{ip}"
        if rate_limited(key, 10, 900):
            raise too_many()
        pin = normalize_pin(data.get("pin"))
        row = None
        if pin:
            row = get_db().execute(
                "SELECT * FROM complaints WHERE pin_hash = ?", (hash_pin(pin),)
            ).fetchone()
        if not row:
            rate_record(key)
            get_db().commit()
            raise ApiError("No complaint matches that tracking code. Please check it and try again.", 404)
        return jsonify(
            ref=ref_for(row["id"]), subject=row["subject"], description=row["description"],
            category=row["category"], custom_text=row["custom_text"], level=row["level"],
            year=row["year"], dept=row["dept"], status=row["status"], remarks=row["remarks"],
            created_at=row["created_at"], updated_at=row["updated_at"],
        )

    # ---- HOD ------------------------------------------------------------
    def serialize_for_hod(row):
        return {
            "id": row["id"], "ref": ref_for(row["id"]), "level": row["level"], "dept": row["dept"],
            "year": row["year"], "category": row["category"], "custom_text": row["custom_text"],
            "student_prn": row["student_prn"], "student_name": row["student_name"] or "Anonymous",
            "subject": row["subject"], "description": row["description"], "status": row["status"],
            "remarks": row["remarks"], "created_at": row["created_at"], "updated_at": row["updated_at"],
        }

    @app.get("/api/hod/complaints")
    @require_role("hod")
    def hod_list():
        level, dept = g.user["level"], g.user["dept"]
        status = request.args.get("status", "all")
        if status != "all" and status not in STATUSES:
            raise ApiError("Invalid status filter.")
        q = (request.args.get("q") or "").strip()[:100]

        db = get_db()
        stats = {s: 0 for s in STATUSES}
        for r in db.execute(
            "SELECT status, COUNT(*) AS n FROM complaints WHERE level = ? AND dept = ? GROUP BY status",
            (level, dept),
        ):
            stats[r["status"]] = r["n"]

        sql = "SELECT * FROM complaints WHERE level = ? AND dept = ?"
        params = [level, dept]
        if status != "all":
            sql += " AND status = ?"
            params.append(status)
        if q:
            pattern = like_pattern(q)
            sql += (
                " AND (lower(subject) LIKE ? ESCAPE '\\' OR lower(category) LIKE ? ESCAPE '\\'"
                " OR lower(COALESCE(custom_text,'')) LIKE ? ESCAPE '\\'"
                " OR lower(COALESCE(student_prn,'')) LIKE ? ESCAPE '\\'"
                " OR lower(COALESCE(student_name,'anonymous')) LIKE ? ESCAPE '\\'"
                " OR lower('AIT-' || printf('%05d', id)) LIKE ? ESCAPE '\\')"
            )
            params += [pattern] * 6
        sql += " ORDER BY id DESC LIMIT 500"
        rows = [serialize_for_hod(r) for r in db.execute(sql, params)]
        return jsonify(
            stats={"total": sum(stats.values()), "pending": stats["Pending"],
                   "in_progress": stats["In Progress"], "resolved": stats["Resolved"]},
            complaints=rows,
        )

    @app.patch("/api/hod/complaints/<int:complaint_id>")
    @require_role("hod")
    def hod_update(complaint_id):
        data = get_json()
        status = choice(data, "status", "status", STATUSES)
        remarks = clean_text(data, "remarks", "Remarks", 1000, multiline=True, required=False)
        db = get_db()
        # Scoped to the HOD's own level+department: other departments look like "not found".
        row = db.execute(
            "SELECT id, status FROM complaints WHERE id = ? AND level = ? AND dept = ?",
            (complaint_id, g.user["level"], g.user["dept"]),
        ).fetchone()
        if not row:
            raise ApiError("Complaint not found.", 404)
        db.execute(
            "UPDATE complaints SET status = ?, remarks = ?, updated_at = ? WHERE id = ?",
            (status, remarks, now_iso(), complaint_id),
        )
        audit(f"hod:{g.user['level']}/{g.user['dept']}", "update_complaint",
              f"{ref_for(complaint_id)}: {row['status']} -> {status}")
        db.commit()
        return jsonify(ok=True)

    @app.get("/api/hod/export")
    @require_role("hod")
    def hod_export():
        level, dept = g.user["level"], g.user["dept"]
        db = get_db()
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["Ref", "Department", "Level", "Year", "Category", "Issue Title", "PRN",
                         "Student Name", "Subject", "Description", "Status", "Remarks",
                         "Submitted (UTC)", "Updated (UTC)"])
        for r in db.execute("SELECT * FROM complaints WHERE level = ? AND dept = ? ORDER BY id", (level, dept)):
            writer.writerow([csv_safe(v) for v in (
                ref_for(r["id"]), r["dept"], r["level"], r["year"], r["category"], r["custom_text"],
                r["student_prn"], r["student_name"] or "Anonymous", r["subject"], r["description"],
                r["status"], r["remarks"], r["created_at"], r["updated_at"])])
        audit(f"hod:{level}/{dept}", "export_csv")
        db.commit()
        slug = re.sub(r"[^A-Za-z0-9]+", "_", dept).strip("_")
        resp = Response("\ufeff" + buf.getvalue(), mimetype="text/csv")
        resp.headers["Content-Disposition"] = f'attachment; filename="AITRC_{level}_{slug}_Grievances.csv"'
        return resp


# --------------------------------------------------------------------------
# CLI helpers  (flask --app app reset-hod-password --level Degree --dept "Mechanical")
# --------------------------------------------------------------------------
def register_cli(app):
    @app.cli.command("reset-hod-password")
    @click.option("--level", type=click.Choice(LEVELS), required=True)
    @click.option("--dept", type=click.Choice(DEPARTMENTS), required=True)
    @click.option("--password", default=None, help="New password (a random one is generated if omitted).")
    def reset_hod_password(level, dept, password):
        password = password or secrets.token_urlsafe(9)
        check_password_policy(password)
        db = get_db()
        cur = db.execute(
            "UPDATE hods SET password_hash = ?, registered = 1, updated_at = ? WHERE level = ? AND dept = ?",
            (hash_password(password), now_iso(), level, dept),
        )
        audit("cli", "reset_hod_password", f"{level}/{dept}")
        db.commit()
        click.echo(f"{level} | {dept} -> new password: {password}" if cur.rowcount else "HOD account not found.")

    @app.cli.command("reopen-hod-registration")
    @click.option("--level", type=click.Choice(LEVELS), default=None, help="Omit with --dept to reopen ALL HODs.")
    @click.option("--dept", type=click.Choice(DEPARTMENTS), default=None)
    def reopen_hod_registration(level, dept):
        """Forgotten HOD password: let that HOD register again (needs the setup code)."""
        db = get_db()
        sql, params = "UPDATE hods SET registered = 0, password_hash = ?, updated_at = ?", [
            generate_password_hash(secrets.token_urlsafe(32), method=current_app.config.get("PASSWORD_HASH_METHOD", "pbkdf2:sha256")),
            now_iso()]
        if level and dept:
            sql += " WHERE level = ? AND dept = ?"; params += [level, dept]
        elif level or dept:
            raise click.UsageError("Give both --level and --dept, or neither (to reopen all).")
        cur = db.execute(sql, params)
        audit("cli", "reopen_hod_registration", f"{level}/{dept}" if level else "all")
        db.commit()
        click.echo(f"{cur.rowcount} HOD account(s) reopened for registration.")

    @app.cli.command("reset-student-password")
    @click.option("--prn", required=True, help="The student's PRN.")
    @click.option("--password", default=None, help="New password (a random one is generated if omitted).")
    def reset_student_password(prn, password):
        password = password or secrets.token_urlsafe(9)
        check_password_policy(password)
        db = get_db()
        cur = db.execute("UPDATE students SET password_hash = ? WHERE prn = ?", (hash_password(password), prn))
        audit("cli", "reset_student_password", prn)
        db.commit()
        click.echo(f"PRN {prn} -> new password: {password}" if cur.rowcount else "Student not found.")


if __name__ == "__main__":
    host = os.environ.get("AITRC_HOST", "127.0.0.1")
    port = int(os.environ.get("AITRC_PORT", "5000"))
    print(f"AITRC portal running at http://{host}:{port}  (Ctrl+C to stop)")
    create_app().run(host=host, port=port, debug=False)
