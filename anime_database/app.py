#!/usr/bin/env python3
"""
app.py — deployable Anikiosk API: read-only anime data + real authentication,
protected by an in-app firewall instead of per-IP rate limiting.

Rate limiting (Flask-Limiter) has been deliberately removed. In its place,
every request passes through a firewall layer (see `firewall()` below) that:

  - blocks known scanner/exploit probe paths (.env, .git, wp-login.php, etc.)
    before they ever reach route logic
  - blocks a blocklist of known attack-tool user agents (sqlmap, nikto, etc.)
  - caps request body size (MAX_CONTENT_LENGTH) to stop oversized payloads
  - requires application/json on every state-changing auth request, which
    also blocks classic HTML-form CSRF (browsers can't set that content type
    on a cross-site form submission)
  - scans the query string and JSON body for common SQLi/XSS/path-traversal
    signatures and rejects matches outright
  - enforces the ALLOWED_ORIGINS allowlist at the server level for anything
    under /api/auth — a disallowed Origin gets a hard 403, not just a
    missing CORS header, so the request never executes
  - strips version-revealing headers where the WSGI layer allows it, and
    adds a strict security header set (CSP, HSTS, frame/embed denial, etc.)

Honest caveat: gunicorn sets its own "Server: gunicorn" header at the HTTP
layer, after the app's response headers are built, so the override below
doesn't reach production the way it does under Flask's dev server — a very
low-severity information leak (knowing it's gunicorn tells an attacker
little). Proxying through Cloudflare (see the deployment notes) hides this
for free, since Cloudflare rewrites the Server header on proxied responses.

Read this as a WAF-style signature/allowlist layer, not traffic shaping —
it blocks requests that *look* malicious, it doesn't throttle by volume. A
consequence worth stating plainly: without rate limiting, brute-forcing a
weak password against /api/auth/login is no longer slowed down by volume
alone — only by the fact that password hashing (scrypt) is deliberately
slow per attempt, and by the account/password rules already enforced.

Two separate SQLite databases, on purpose:
  - anime.db  — the ingested MyAnimeList/Jikan catalog. Opened strictly
                READ-ONLY (SQLite's "mode=ro" URI). Safe to commit to your repo.
  - app.db    — everything user-generated: accounts, sessions, polls, forum
                threads/comments, communities, and community-submitted
                characters. Created automatically. NEVER commit this file.

This now also holds the community features that used to live in the
frontend artifact's browser-only window.storage (which only exists inside
Claude.ai's own preview and silently does nothing anywhere else, including
on Netlify). Polls, forum threads/comments, communities, and community
character submissions are real tables here now, gated by the same session
auth as the profile endpoints — no more silent no-ops off Claude.ai.

Run locally:
    python anime_database/app.py

Production:
    gunicorn app:app

Required environment variables in production:
    SECRET_KEY      — a long random string (see previous version's notes).
    ALLOWED_ORIGINS — comma-separated list of origins allowed to call the
                       authenticated endpoints, e.g. "https://anikiosk.netlify.app".

Optional: DB_PATH, APP_DB_PATH, PORT.
"""

import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
import uuid
from functools import wraps

from flask import Flask, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "anime.db"))
APP_DB_PATH = os.environ.get("APP_DB_PATH", os.path.join(BASE_DIR, "app.db"))
PAGE_SIZE = 25

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    print("WARNING: SECRET_KEY not set — using a random throwaway key for this "
          "process only. Set a real SECRET_KEY in production.")

ALLOWED_ORIGINS = set(
    o.strip() for o in os.environ.get(
        "ALLOWED_ORIGINS",
        "https://anikiosk.netlify.app,http://localhost:5500,http://127.0.0.1:5500,http://localhost:8787",
    ).split(",") if o.strip()
)

SESSION_COOKIE_NAME = "anikiosk_session"
SESSION_LIFETIME_SECONDS = 7 * 24 * 3600  # 7 days

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,24}$")
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 128  # hashing is deliberately slow (scrypt); cap input to avoid a cheap DoS vector
MAX_IMAGE_DATA_LEN = 350_000  # leaves headroom under the 400KB MAX_CONTENT_LENGTH for JSON structure overhead

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = 400 * 1024  # 400KB — covers a resized/compressed character-avatar upload (base64 JPEG) with headroom; everything else here is tiny


# ============================================================== firewall

BLOCKED_PATH_PATTERNS = [
    r"\.env", r"\.git", r"wp-login", r"wp-admin", r"wp-content", r"phpmyadmin",
    r"\.php$", r"\.aws", r"\.ssh", r"xmlrpc\.php", r"config\.json", r"\.htaccess",
    r"docker-compose", r"\.DS_Store", r"vendor/", r"\.well-known/(?!acme-challenge)",
]
BLOCKED_PATH_RE = re.compile("|".join(BLOCKED_PATH_PATTERNS), re.IGNORECASE)

BLOCKED_USER_AGENTS = [
    "sqlmap", "nikto", "nessus", "nmap", "masscan", "zgrab", "gobuster",
    "dirbuster", "acunetix", "w3af", "havij", "wpscan", "nuclei",
]

INJECTION_PATTERNS = [
    r"union\s+select", r"drop\s+table", r"insert\s+into", r"--\s*$",
    r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=",
    r"\.\./\.\./", r"/etc/passwd", r";\s*shutdown", r"exec\s*\(", r"eval\s*\(",
    r"base64_decode", r"\bor\s+1\s*=\s*1\b",
]
INJECTION_RE = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE)


def _contains_injection(value):
    return isinstance(value, str) and bool(INJECTION_RE.search(value))


def _scan_json_for_injection(data, depth=0):
    if depth > 6:
        return False
    if isinstance(data, str):
        return _contains_injection(data)
    if isinstance(data, dict):
        return any(_scan_json_for_injection(v, depth + 1) for v in data.values())
    if isinstance(data, list):
        return any(_scan_json_for_injection(v, depth + 1) for v in data)
    return False


@app.before_request
def firewall():
    path = request.path
    ua = (request.headers.get("User-Agent") or "").lower()
    origin = request.headers.get("Origin")

    # 1. Known scanner/exploit probe paths — block before any route logic runs.
    if BLOCKED_PATH_RE.search(path):
        return jsonify({"error": "forbidden"}), 403

    # 2. Known attack-tool user agents.
    if any(bad in ua for bad in BLOCKED_USER_AGENTS):
        return jsonify({"error": "forbidden"}), 403

    # 3. Any state-changing request under /api: enforce the origin allowlist
    #    server-side, not just via the CORS response header, so a disallowed
    #    browser origin can't even trigger the write (hiding the response
    #    alone isn't enough — the write would still have happened).
    if path.startswith("/api") and request.method in ("POST", "PATCH", "DELETE") and origin and origin not in ALLOWED_ORIGINS:
        return jsonify({"error": "origin not allowed"}), 403

    # 4. Every state-changing request must be real JSON — this is also what
    #    blocks classic HTML-form CSRF, since a cross-site <form> POST can't
    #    set Content-Type: application/json without triggering a (blocked)
    #    CORS preflight.
    if path.startswith("/api") and request.method in ("POST", "PATCH", "DELETE"):
        if not request.is_json:
            return jsonify({"error": "expected application/json"}), 415

    # 5. Signature-based injection screening across the query string and JSON body.
    for v in request.args.values():
        if _contains_injection(v):
            return jsonify({"error": "forbidden"}), 403
    if request.method in ("POST", "PATCH") and request.is_json:
        body = request.get_json(silent=True)
        if body is not None and _scan_json_for_injection(body):
            return jsonify({"error": "forbidden"}), 403


@app.after_request
def add_headers(resp):
    origin = request.headers.get("Origin")
    if origin and origin in ALLOWED_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Vary"] = "Origin"
    elif request.path.startswith("/api/") and not request.path.startswith("/api/auth"):
        # Public read-only anime data can be fetched from anywhere; only
        # cookie-carrying auth endpoints are restricted to known origins.
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Cross-Origin-Resource-Policy"] = "cross-origin"

    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, OPTIONS"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer-when-downgrade"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=()"
    resp.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    resp.headers["Server"] = "anikiosk"  # don't advertise Werkzeug/gunicorn/Python versions
    return resp


@app.route("/api/<path:_any>", methods=["OPTIONS"])
def cors_preflight(_any):
    return ("", 204)


@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": "forbidden"}), 403


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "not found"}), 404


@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "request too large"}), 413


@app.errorhandler(415)
def unsupported_media(e):
    return jsonify({"error": "unsupported content type"}), 415


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "internal server error"}), 500


# ============================================================== databases

def get_anime_db():
    """Read-only connection to the ingested catalog — a bug or bad query
    here can never mutate the dataset, only fail to read it."""
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def get_app_db():
    conn = sqlite3.connect(APP_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


APP_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    avatar_seed   TEXT NOT NULL,
    bio           TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS polls (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    question   TEXT NOT NULL,
    author     TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS poll_options (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    poll_id  INTEGER NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
    text     TEXT NOT NULL,
    position INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS poll_votes (
    poll_id   INTEGER NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
    option_id INTEGER NOT NULL REFERENCES poll_options(id) ON DELETE CASCADE,
    username  TEXT NOT NULL,
    voted_at  INTEGER NOT NULL,
    PRIMARY KEY (poll_id, username)
);

CREATE TABLE IF NOT EXISTS communities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    author      TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS community_members (
    community_id INTEGER NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    username     TEXT NOT NULL,
    joined_at    INTEGER NOT NULL,
    PRIMARY KEY (community_id, username)
);

CREATE TABLE IF NOT EXISTS threads (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    community_id  INTEGER REFERENCES communities(id) ON DELETE CASCADE,
    title         TEXT NOT NULL,
    body          TEXT NOT NULL,
    video         TEXT,
    author        TEXT NOT NULL,
    author_avatar TEXT,
    created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS comments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id  INTEGER NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    author     TEXT NOT NULL,
    text       TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS community_characters (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    anime      TEXT,
    note       TEXT NOT NULL,
    image_data TEXT,
    author     TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
"""


def init_app_db():
    conn = get_app_db()
    conn.executescript(APP_SCHEMA)
    conn.commit()
    conn.close()
    try:
        os.chmod(APP_DB_PATH, 0o600)  # owner read/write only — this file holds password hashes
    except OSError:
        pass


init_app_db()


# ============================================================== auth helpers

def hash_token(raw_token):
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def create_session(user_id):
    raw_token = secrets.token_urlsafe(32)
    now = int(time.time())
    conn = get_app_db()
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)",
        (hash_token(raw_token), user_id, now, now + SESSION_LIFETIME_SECONDS),
    )
    conn.commit()
    conn.close()
    return raw_token


def get_user_from_token(raw_token):
    if not raw_token:
        return None
    conn = get_app_db()
    row = conn.execute(
        "SELECT s.expires_at, u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash=?",
        (hash_token(raw_token),),
    ).fetchone()
    conn.close()
    if not row or row["expires_at"] < time.time():
        return None
    return row


def public_user(row):
    return {
        "username": row["username"],
        "avatarSeed": row["avatar_seed"],
        "bio": row["bio"],
        "joinedAt": row["created_at"] * 1000,
    }


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.cookies.get(SESSION_COOKIE_NAME)
        user = get_user_from_token(token)
        if not user:
            return jsonify({"error": "not authenticated"}), 401
        g.user = user
        return fn(*args, **kwargs)
    return wrapper


def current_username_optional():
    """For public GET endpoints that personalize their response (e.g. 'did I
    already vote on this poll') without requiring the visitor to be signed in."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    user = get_user_from_token(token)
    return user["username"] if user else None


def set_session_cookie(resp, token):
    resp.set_cookie(
        SESSION_COOKIE_NAME, token, max_age=SESSION_LIFETIME_SECONDS,
        httponly=True, secure=True, samesite="None", path="/",
    )
    return resp


# ============================================================== auth endpoints

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not USERNAME_RE.match(username):
        return jsonify({"error": "usernames are 3-24 characters: letters, numbers, underscore only"}), 400
    if len(password) < MIN_PASSWORD_LEN:
        return jsonify({"error": f"password must be at least {MIN_PASSWORD_LEN} characters"}), 400
    if len(password) > MAX_PASSWORD_LEN:
        return jsonify({"error": f"password must be under {MAX_PASSWORD_LEN} characters"}), 400

    conn = get_app_db()
    existing = conn.execute("SELECT 1 FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone()
    if existing:
        conn.close()
        return jsonify({"error": "that username is taken"}), 409

    now = int(time.time())
    conn.execute(
        "INSERT INTO users (username, password_hash, avatar_seed, bio, created_at) VALUES (?,?,?,?,?)",
        (username, generate_password_hash(password), f"{username}-{now}", "", now),
    )
    conn.commit()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()

    token = create_session(user["id"])
    return set_session_cookie(jsonify(public_user(user)), token)


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "")[:MAX_PASSWORD_LEN]

    conn = get_app_db()
    user = conn.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone()
    conn.close()

    # Deliberately the same error whether the username doesn't exist or the
    # password is wrong — don't let this endpoint be used to enumerate accounts.
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "invalid username or password"}), 401

    token = create_session(user["id"])
    return set_session_cookie(jsonify(public_user(user)), token)


@app.route("/api/auth/logout", methods=["POST"])
def logout():
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        conn = get_app_db()
        conn.execute("DELETE FROM sessions WHERE token_hash=?", (hash_token(token),))
        conn.commit()
        conn.close()
    resp = jsonify({"ok": True})
    resp.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return resp


@app.route("/api/auth/me", methods=["GET"])
@login_required
def me():
    return jsonify(public_user(g.user))


@app.route("/api/auth/me", methods=["PATCH"])
@login_required
def update_me():
    data = request.get_json(silent=True) or {}
    fields, values = [], []
    if "avatarSeed" in data:
        fields.append("avatar_seed=?"); values.append(str(data["avatarSeed"])[:120])
    if "bio" in data:
        fields.append("bio=?"); values.append(str(data["bio"])[:500])
    if not fields:
        return jsonify(public_user(g.user))
    values.append(g.user["id"])
    conn = get_app_db()
    conn.execute(f"UPDATE users SET {', '.join(fields)} WHERE id=?", values)
    conn.commit()
    row = conn.execute("SELECT * FROM users WHERE id=?", (g.user["id"],)).fetchone()
    conn.close()
    return jsonify(public_user(row))


# ============================================================== community features
# Polls, forum threads/comments, communities, and community-submitted
# characters. These used to live in the frontend artifact's browser-only
# window.storage — which only exists inside Claude.ai's preview and is a
# silent no-op anywhere else a static copy of the HTML is hosted (Netlify
# included). They're real, durable data here now, in the same app.db as
# accounts, gated by the same session cookie.

def slugify(name):
    s = re.sub(r"[^a-z0-9]+", "-", name.lower().strip()).strip("-")
    return (s[:40] or "community")


def new_slug(conn, name):
    base = slugify(name)
    candidate = base
    i = 2
    while conn.execute("SELECT 1 FROM communities WHERE slug=?", (candidate,)).fetchone():
        candidate = f"{base}-{i}"
        i += 1
    return candidate


# ---- polls ---------------------------------------------------------------

def poll_json(conn, p):
    options = conn.execute(
        "SELECT * FROM poll_options WHERE poll_id=? ORDER BY position", (p["id"],)
    ).fetchall()
    vote_rows = conn.execute(
        "SELECT option_id, username FROM poll_votes WHERE poll_id=?", (p["id"],)
    ).fetchall()
    votes = {str(o["id"]): 0 for o in options}
    voters = []
    for v in vote_rows:
        votes[str(v["option_id"])] = votes.get(str(v["option_id"]), 0) + 1
        voters.append(v["username"])
    return {
        "id": str(p["id"]),
        "question": p["question"],
        "options": [{"id": str(o["id"]), "text": o["text"]} for o in options],
        "votes": votes,
        "voters": voters,
        "author": p["author"],
        "createdAt": p["created_at"] * 1000,
    }


@app.route("/api/polls")
def list_polls():
    conn = get_app_db()
    rows = conn.execute("SELECT * FROM polls ORDER BY created_at DESC").fetchall()
    result = [poll_json(conn, p) for p in rows]
    conn.close()
    return jsonify(result)


@app.route("/api/polls", methods=["POST"])
@login_required
def create_poll():
    data = request.get_json(silent=True) or {}
    question = (data.get("question") or "").strip()[:300]
    options = [str(o).strip()[:120] for o in (data.get("options") or []) if str(o).strip()][:8]
    if not question or len(options) < 2:
        return jsonify({"error": "a question and at least two options are required"}), 400

    now = int(time.time())
    conn = get_app_db()
    cur = conn.execute(
        "INSERT INTO polls (question, author, created_at) VALUES (?,?,?)",
        (question, g.user["username"], now),
    )
    poll_id = cur.lastrowid
    for i, text in enumerate(options):
        conn.execute(
            "INSERT INTO poll_options (poll_id, text, position) VALUES (?,?,?)",
            (poll_id, text, i),
        )
    conn.commit()
    row = conn.execute("SELECT * FROM polls WHERE id=?", (poll_id,)).fetchone()
    result = poll_json(conn, row)
    conn.close()
    return jsonify(result)


@app.route("/api/polls/<int:poll_id>/vote", methods=["POST"])
@login_required
def vote_poll(poll_id):
    data = request.get_json(silent=True) or {}
    try:
        option_id = int(data.get("optionId"))
    except (TypeError, ValueError):
        return jsonify({"error": "invalid option"}), 400

    conn = get_app_db()
    poll = conn.execute("SELECT 1 FROM polls WHERE id=?", (poll_id,)).fetchone()
    opt = conn.execute(
        "SELECT 1 FROM poll_options WHERE id=? AND poll_id=?", (option_id, poll_id)
    ).fetchone()
    if not poll or not opt:
        conn.close()
        return jsonify({"error": "not found"}), 404
    try:
        conn.execute(
            "INSERT INTO poll_votes (poll_id, option_id, username, voted_at) VALUES (?,?,?,?)",
            (poll_id, option_id, g.user["username"], int(time.time())),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "you already voted on this poll"}), 409
    row = conn.execute("SELECT * FROM polls WHERE id=?", (poll_id,)).fetchone()
    result = poll_json(conn, row)
    conn.close()
    return jsonify(result)


# ---- communities -----------------------------------------------------------

def community_json(conn, c):
    members = [
        m["username"] for m in
        conn.execute("SELECT username FROM community_members WHERE community_id=?", (c["id"],)).fetchall()
    ]
    return {
        "id": str(c["id"]),
        "name": c["name"],
        "slug": c["slug"],
        "description": c["description"] or "",
        "createdBy": c["author"],
        "createdAt": c["created_at"] * 1000,
        "members": members,
    }


@app.route("/api/communities")
def list_communities():
    conn = get_app_db()
    rows = conn.execute("SELECT * FROM communities ORDER BY created_at DESC").fetchall()
    result = [community_json(conn, c) for c in rows]
    conn.close()
    return jsonify(result)


@app.route("/api/communities/<int:community_id>")
def get_community(community_id):
    conn = get_app_db()
    row = conn.execute("SELECT * FROM communities WHERE id=?", (community_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "not found"}), 404
    result = community_json(conn, row)
    conn.close()
    return jsonify(result)


@app.route("/api/communities", methods=["POST"])
@login_required
def create_community():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()[:40]
    description = (data.get("description") or "").strip()[:240]
    if not name:
        return jsonify({"error": "a community name is required"}), 400

    now = int(time.time())
    conn = get_app_db()
    slug = new_slug(conn, name)
    cur = conn.execute(
        "INSERT INTO communities (name, slug, description, author, created_at) VALUES (?,?,?,?,?)",
        (name, slug, description, g.user["username"], now),
    )
    community_id = cur.lastrowid
    conn.execute(
        "INSERT INTO community_members (community_id, username, joined_at) VALUES (?,?,?)",
        (community_id, g.user["username"], now),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM communities WHERE id=?", (community_id,)).fetchone()
    result = community_json(conn, row)
    conn.close()
    return jsonify(result)


@app.route("/api/communities/<int:community_id>/join", methods=["POST"])
@login_required
def join_community(community_id):
    conn = get_app_db()
    exists = conn.execute("SELECT 1 FROM communities WHERE id=?", (community_id,)).fetchone()
    if not exists:
        conn.close()
        return jsonify({"error": "not found"}), 404
    try:
        conn.execute(
            "INSERT INTO community_members (community_id, username, joined_at) VALUES (?,?,?)",
            (community_id, g.user["username"], int(time.time())),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # already a member — joining again is a harmless no-op
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/communities/<int:community_id>/leave", methods=["POST"])
@login_required
def leave_community(community_id):
    conn = get_app_db()
    conn.execute(
        "DELETE FROM community_members WHERE community_id=? AND username=?",
        (community_id, g.user["username"]),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# ---- forum threads & comments ----------------------------------------------

def thread_json(t):
    return {
        "id": str(t["id"]),
        "title": t["title"],
        "body": t["body"],
        "video": t["video"] or "",
        "communityId": str(t["community_id"]) if t["community_id"] is not None else None,
        "author": t["author"],
        "authorAvatar": t["author_avatar"] or t["author"],
        "createdAt": t["created_at"] * 1000,
    }


def comment_json(c):
    return {"author": c["author"], "text": c["text"], "createdAt": c["created_at"] * 1000}


@app.route("/api/threads")
def list_threads():
    community_id = request.args.get("communityId")
    conn = get_app_db()
    if community_id:
        rows = conn.execute(
            "SELECT * FROM threads WHERE community_id=? ORDER BY created_at DESC", (community_id,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM threads ORDER BY created_at DESC").fetchall()
    conn.close()
    return jsonify([thread_json(t) for t in rows])


@app.route("/api/threads/<int:thread_id>")
def get_thread(thread_id):
    conn = get_app_db()
    row = conn.execute("SELECT * FROM threads WHERE id=?", (thread_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "not found"}), 404
    comments = conn.execute(
        "SELECT * FROM comments WHERE thread_id=? ORDER BY created_at ASC", (thread_id,)
    ).fetchall()
    community = None
    if row["community_id"] is not None:
        crow = conn.execute("SELECT * FROM communities WHERE id=?", (row["community_id"],)).fetchone()
        if crow:
            community = {"id": str(crow["id"]), "name": crow["name"]}
    conn.close()
    return jsonify({
        "thread": thread_json(row),
        "comments": [comment_json(c) for c in comments],
        "community": community,
    })


@app.route("/api/threads", methods=["POST"])
@login_required
def create_thread():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()[:140]
    body = (data.get("body") or "").strip()[:5000]
    video = (data.get("video") or "").strip()[:500]
    community_id = data.get("communityId") or None
    if not title or not body:
        return jsonify({"error": "a title and body are required"}), 400
    if community_id is not None:
        try:
            community_id = int(community_id)
        except (TypeError, ValueError):
            community_id = None

    now = int(time.time())
    conn = get_app_db()
    if community_id is not None:
        exists = conn.execute("SELECT 1 FROM communities WHERE id=?", (community_id,)).fetchone()
        if not exists:
            community_id = None
    cur = conn.execute(
        "INSERT INTO threads (community_id, title, body, video, author, author_avatar, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (community_id, title, body, video, g.user["username"], g.user["avatar_seed"], now),
    )
    thread_id = cur.lastrowid
    conn.commit()
    row = conn.execute("SELECT * FROM threads WHERE id=?", (thread_id,)).fetchone()
    result = thread_json(row)
    conn.close()
    return jsonify(result)


@app.route("/api/threads/<int:thread_id>/comments", methods=["POST"])
@login_required
def add_comment(thread_id):
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()[:2000]
    if not text:
        return jsonify({"error": "comment text is required"}), 400
    conn = get_app_db()
    exists = conn.execute("SELECT 1 FROM threads WHERE id=?", (thread_id,)).fetchone()
    if not exists:
        conn.close()
        return jsonify({"error": "not found"}), 404
    now = int(time.time())
    conn.execute(
        "INSERT INTO comments (thread_id, author, text, created_at) VALUES (?,?,?,?)",
        (thread_id, g.user["username"], text, now),
    )
    conn.commit()
    comments = conn.execute(
        "SELECT * FROM comments WHERE thread_id=? ORDER BY created_at ASC", (thread_id,)
    ).fetchall()
    result = [comment_json(c) for c in comments]
    conn.close()
    return jsonify(result)


# ---- community-submitted characters ----------------------------------------

def community_character_json(c):
    return {
        "id": str(c["id"]),
        "name": c["name"],
        "anime": c["anime"] or "",
        "note": c["note"],
        "imageData": c["image_data"] or "",
        "author": c["author"],
        "createdAt": c["created_at"] * 1000,
    }


@app.route("/api/community-characters")
def list_community_characters():
    conn = get_app_db()
    rows = conn.execute("SELECT * FROM community_characters ORDER BY created_at DESC").fetchall()
    conn.close()
    return jsonify([community_character_json(c) for c in rows])


@app.route("/api/community-characters", methods=["POST"])
@login_required
def create_community_character():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()[:60]
    anime = (data.get("anime") or "").strip()[:80]
    note = (data.get("note") or "").strip()[:500]
    image_data = data.get("imageData") or ""
    if not name or not note:
        return jsonify({"error": "a name and note are required"}), 400
    if len(image_data) > MAX_IMAGE_DATA_LEN:
        return jsonify({"error": "that picture is too large — try a smaller image"}), 400

    now = int(time.time())
    conn = get_app_db()
    cur = conn.execute(
        "INSERT INTO community_characters (name, anime, note, image_data, author, created_at) "
        "VALUES (?,?,?,?,?,?)",
        (name, anime, note, image_data, g.user["username"], now),
    )
    char_id = cur.lastrowid
    conn.commit()
    row = conn.execute("SELECT * FROM community_characters WHERE id=?", (char_id,)).fetchone()
    result = community_character_json(row)
    conn.close()
    return jsonify(result)


# ============================================================== anime data endpoints (read-only, public)

def row_to_anime(row):
    genres = json.loads(row["genres"]) if row["genres"] else []
    return {
        "mal_id": row["mal_id"], "title": row["title"], "title_japanese": row["title_japanese"],
        "type": row["type"], "episodes": row["episodes"], "score": row["score"], "status": row["status"],
        "year": int(row["aired_from"][:4]) if row["aired_from"] else None,
        "aired": {"from": row["aired_from"], "to": row["aired_to"], "string": row["aired_string"]},
        "synopsis": row["synopsis"], "genres": [{"name": g} for g in genres], "themes": [],
        "images": {"jpg": {"image_url": row["image_url"], "large_image_url": row["image_url"]}},
        "source": row["source"],
    }


@app.route("/api/status")
def status():
    if not os.path.exists(DB_PATH):
        return jsonify({"ok": False, "error": "database file not found on server"}), 500
    conn = get_anime_db()
    count = conn.execute("SELECT COUNT(*) c FROM anime").fetchone()["c"]
    conn.close()
    return jsonify({"ok": True, "anime_count": count})


@app.route("/api/top-anime")
def top_anime():
    page = max(1, int(request.args.get("page", 1)))
    offset = (page - 1) * PAGE_SIZE
    conn = get_anime_db()
    rows = conn.execute(
        "SELECT * FROM anime ORDER BY (score IS NULL), score DESC LIMIT ? OFFSET ?",
        (PAGE_SIZE, offset),
    ).fetchall()
    conn.close()
    return jsonify([row_to_anime(r) for r in rows])


@app.route("/api/search")
def search():
    q = request.args.get("q", "")[:100]
    conn = get_anime_db()
    rows = conn.execute(
        "SELECT * FROM anime WHERE title LIKE ? OR title_japanese LIKE ? "
        "ORDER BY (score IS NULL), score DESC LIMIT 15",
        (f"%{q}%", f"%{q}%"),
    ).fetchall()
    conn.close()
    return jsonify([row_to_anime(r) for r in rows])


@app.route("/api/top-characters")
def top_characters():
    limit = min(50, max(1, int(request.args.get("limit", 10))))
    conn = get_anime_db()
    rows = conn.execute(
        """
        SELECT c.*, a.score AS anime_score FROM characters c
        JOIN anime a ON a.mal_id = c.anime_mal_id
        WHERE c.role = 'Main'
        ORDER BY (a.score IS NULL), a.score DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return jsonify([
        {"mal_id": r["character_mal_id"], "name": r["name"],
         "images": {"jpg": {"image_url": r["image_url"]}}, "about": None}
        for r in rows
    ])


@app.route("/api/anime/<int:anime_id>")
def anime_detail(anime_id):
    conn = get_anime_db()
    row = conn.execute("SELECT * FROM anime WHERE mal_id=?", (anime_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(row_to_anime(row))


@app.route("/api/anime/<int:anime_id>/characters")
def anime_characters(anime_id):
    conn = get_anime_db()
    rows = conn.execute("SELECT * FROM characters WHERE anime_mal_id=?", (anime_id,)).fetchall()
    conn.close()
    return jsonify([
        {"character": {"mal_id": r["character_mal_id"], "name": r["name"],
                        "images": {"jpg": {"image_url": r["image_url"]}}},
         "role": r["role"]}
        for r in rows
    ])


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8787))
    print(f"Anime data (read-only): {DB_PATH}")
    print(f"App data (users/sessions, mode 0600): {APP_DB_PATH}")
    print(f"Allowed origins for authenticated requests: {sorted(ALLOWED_ORIGINS)}")
    print(f"Serving at http://localhost:{port}  (Ctrl+C to stop)")
    app.run(host="0.0.0.0", port=port, debug=False)
