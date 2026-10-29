"""auth.py - local user accounts for the Scene scanner (SQLite).

Stores per user: username, email, salted PBKDF2 password hash, a recovery code
(also hashed), and a scan history. Passwords are never stored in plain text.
Existing users.db files are upgraded in place by init_db().
"""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
import unicodedata
from contextlib import closing

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")
ITERATIONS = 600_000            # PBKDF2-HMAC-SHA256; older rows upgrade on login
MIN_PW, MAX_PW = 8, 256
MAX_FAILS = 5                   # wrong attempts before a temporary lock
LOCK_SECONDS = 300
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DUMMY_SALT = os.urandom(16)    # used to keep timing equal for unknown usernames

# columns added after the first version of the table (init_db adds what's missing)
_NEW_COLUMNS = {
    "email": "TEXT",
    "iterations": "INTEGER NOT NULL DEFAULT 200000",
    "rec_iterations": "INTEGER NOT NULL DEFAULT 200000",
    "failed_attempts": "INTEGER NOT NULL DEFAULT 0",
    "locked_until": "REAL NOT NULL DEFAULT 0",
}


def _connect():
    db = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    with closing(_connect()) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
                salt          BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                rec_salt      BLOB,
                rec_hash      BLOB,
                created_at    TEXT DEFAULT CURRENT_TIMESTAMP
            )""")
        have = {r["name"] for r in db.execute("PRAGMA table_info(users)")}
        for name, ddl in _NEW_COLUMNS.items():
            if name not in have:
                db.execute(f"ALTER TABLE users ADD COLUMN {name} {ddl}")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email "
                   "ON users(email COLLATE NOCASE)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id       INTEGER NOT NULL REFERENCES users(id),
                finished_at   TEXT DEFAULT CURRENT_TIMESTAMP,
                mode          TEXT,
                files_checked INTEGER,
                threats       INTEGER,
                status        TEXT
            )""")
    try:
        os.chmod(DB_PATH, 0o600)
    except OSError:
        pass


def _hash(text, salt, iterations=None):
    return hashlib.pbkdf2_hmac("sha256", text.encode("utf-8"), salt, iterations or ITERATIONS)


def _new_code():
    raw = secrets.token_hex(10).upper()             # 80 bits: A1B2-C3D4-E5F6-A7B8-C9D0
    return "-".join(raw[i:i + 4] for i in range(0, 20, 4))


def _clean_code(code):
    return "".join(ch for ch in code.upper() if ch.isalnum())


def _s(value):
    return unicodedata.normalize("NFKC", value).strip() if isinstance(value, str) else ""


def _check_password(pw):
    if not isinstance(pw, str) or len(pw) < MIN_PW:
        return f"Password must be at least {MIN_PW} characters."
    if len(pw) > MAX_PW:
        return f"Password must be at most {MAX_PW} characters."
    return None


def _lock_msg(row):
    mins = max(1, int((row["locked_until"] - time.time()) // 60) + 1)
    return f"Too many failed attempts. Try again in about {mins} min."


def _record_failure(db, row):
    fails = row["failed_attempts"] + 1
    if fails >= MAX_FAILS:
        db.execute("UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?",
                   (time.time() + LOCK_SECONDS, row["id"]))
    else:
        db.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (fails, row["id"]))


def _public(row):
    return {"id": row["id"], "username": row["username"],
            "email": row["email"], "created_at": row["created_at"]}


def register_user(username, email, password):
    username, email = _s(username), _s(email)
    if not 3 <= len(username) <= 32:
        return False, "Username must be 3-32 characters.", None
    if len(email) > 254 or not EMAIL_RE.match(email):
        return False, "Enter a valid email address.", None
    err = _check_password(password)
    if err:
        return False, err, None
    salt, rec_salt, code = os.urandom(16), os.urandom(16), _new_code()
    try:
        with closing(_connect()) as db:
            db.execute(
                "INSERT INTO users (username, email, salt, password_hash, iterations, "
                "rec_salt, rec_hash, rec_iterations) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (username, email, salt, _hash(password, salt), ITERATIONS,
                 rec_salt, _hash(_clean_code(code), rec_salt), ITERATIONS))
    except sqlite3.IntegrityError as e:
        if "email" in str(e).lower():
            return False, "That email is already registered.", None
        return False, "That username is already taken.", None
    return True, "Account created.", code


def verify_user(username, password):
    bad = (None, "Wrong username or password.")
    username = _s(username)
    if not isinstance(password, str) or len(password) > MAX_PW:
        return bad
    with closing(_connect()) as db:
        row = db.execute("SELECT * FROM users WHERE username = ? OR email = ? COLLATE NOCASE", (username, username)).fetchone()
        if row is None:
            _hash(password, _DUMMY_SALT)
            return bad
        if row["locked_until"] > time.time():
            return None, _lock_msg(row)
        if not hmac.compare_digest(_hash(password, row["salt"], row["iterations"]),
                                   row["password_hash"]):
            _record_failure(db, row)
            return bad
        if row["iterations"] < ITERATIONS:
            salt = os.urandom(16)
            db.execute("UPDATE users SET salt = ?, password_hash = ?, iterations = ?, "
                       "failed_attempts = 0 WHERE id = ?",
                       (salt, _hash(password, salt), ITERATIONS, row["id"]))
        elif row["failed_attempts"]:
            db.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (row["id"],))
        return _public(row), "Logged in."


def reset_password(username, code, new_password):
    err = _check_password(new_password)
    if err:
        return False, err, None
    bad = (False, "Username or recovery code is incorrect.", None)
    username = _s(username)
    code = _clean_code(code) if isinstance(code, str) and len(code) <= 64 else ""
    with closing(_connect()) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT * FROM users WHERE username = ? OR email = ? COLLATE NOCASE", (username, username)).fetchone()
        if row is None:
            _hash(code, _DUMMY_SALT)
            db.execute("ROLLBACK")
            return bad
        if row["locked_until"] > time.time():
            db.execute("ROLLBACK")
            return False, _lock_msg(row), None
        if (row["rec_salt"] is None or row["rec_hash"] is None or not code or
                not hmac.compare_digest(_hash(code, row["rec_salt"], row["rec_iterations"]),
                                        row["rec_hash"])):
            _record_failure(db, row)
            db.execute("COMMIT")
            return bad
        salt, rec_salt, new_code = os.urandom(16), os.urandom(16), _new_code()
        db.execute(
            "UPDATE users SET salt = ?, password_hash = ?, iterations = ?, rec_salt = ?, "
            "rec_hash = ?, rec_iterations = ?, failed_attempts = 0, locked_until = 0 "
            "WHERE id = ?",
            (salt, _hash(new_password, salt), ITERATIONS, rec_salt,
             _hash(_clean_code(new_code), rec_salt), ITERATIONS, row["id"]))
        db.execute("COMMIT")
    return True, "Password changed.", new_code


def get_profile(user_id):
    with closing(_connect()) as db:
        row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            return None
        t = db.execute("SELECT COUNT(*) AS n, COALESCE(SUM(files_checked),0) AS total_files, COALESCE(SUM(threats),0) AS threats "
                       "FROM scans WHERE user_id = ?", (user_id,)).fetchone()
    profile = _public(row)
    profile.update(scan_count=t["n"], total_files=t["total_files"], total_threats=t["threats"])
    return profile


def add_scan(user_id, mode, files_checked, threats, status):
    with closing(_connect()) as db:
        db.execute("INSERT INTO scans (user_id, mode, files_checked, threats, status) "
                   "VALUES (?, ?, ?, ?, ?)", (user_id, mode, files_checked, threats, status))
        db.execute("COMMIT")


def get_scans(user_id, limit=20):
    with closing(_connect()) as db:
        rows = db.execute("SELECT finished_at, mode, files_checked, threats, status "
                          "FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT ?",
                          (user_id, limit)).fetchall()
    return [dict(r) for r in rows]
