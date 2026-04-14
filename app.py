"""
URL Shortener - Flask Backend
Endpoints:
  POST   /api/auth/register
  POST   /api/auth/login
  POST   /api/links          (auth required)
  GET    /api/links          (auth required)
  DELETE /api/links/<id>     (auth required)
  GET    /api/links/<id>/stats (auth required)
  GET    /<code>             → redirect
  GET    /                  → serves frontend
"""

import os
import sqlite3
import string
import random
import datetime
import re
from functools import wraps

import bcrypt
import jwt
from flask import Flask, request, jsonify, redirect, send_from_directory, g
from flask_cors import CORS

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SECRET_KEY = "url-shortener-super-secret-key-change-in-prod"
DB_PATH = os.path.join(os.path.dirname(__file__), "shortener.db")
BASE_URL = "http://localhost:5000"

app = Flask(__name__, static_folder="public", static_url_path="")
CORS(app)
app.config["SECRET_KEY"] = SECRET_KEY

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    NOT NULL UNIQUE,
            email       TEXT    NOT NULL UNIQUE,
            password_hash TEXT  NOT NULL,
            created_at  TEXT    DEFAULT (datetime('now'))
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS links (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            original_url TEXT   NOT NULL,
            short_code  TEXT    NOT NULL UNIQUE,
            title       TEXT,
            click_count INTEGER DEFAULT 0,
            created_at  TEXT    DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS clicks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            link_id     INTEGER NOT NULL,
            clicked_at  TEXT    DEFAULT (datetime('now')),
            referrer    TEXT,
            user_agent  TEXT,
            FOREIGN KEY (link_id) REFERENCES links(id)
        )
    """)
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def generate_token(user_id: int, username: str) -> str:
    payload = {
        "user_id": user_id,
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid token"}), 401
        token = auth_header.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            g.current_user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Short code generation
# ---------------------------------------------------------------------------

def generate_short_code(length=6) -> str:
    chars = string.ascii_letters + string.digits
    db = get_db()
    while True:
        code = "".join(random.choices(chars, k=length))
        existing = db.execute("SELECT id FROM links WHERE short_code = ?", (code,)).fetchone()
        if not existing:
            return code


def is_valid_url(url: str) -> bool:
    pattern = re.compile(
        r"^(https?://)?"
        r"(([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,})"
        r"(:\d+)?"
        r"(/[^\s]*)?"
        r"$"
    )
    return bool(pattern.match(url))


# ---------------------------------------------------------------------------
# Auth Routes
# ---------------------------------------------------------------------------

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not username or not email or not password:
        return jsonify({"error": "All fields are required"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    db = get_db()
    existing = db.execute(
        "SELECT id FROM users WHERE username = ? OR email = ?", (username, email)
    ).fetchone()
    if existing:
        return jsonify({"error": "Username or email already exists"}), 409

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    cur = db.execute(
        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
        (username, email, hashed),
    )
    db.commit()

    token = generate_token(cur.lastrowid, username)
    return jsonify({"token": token, "username": username}), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user or not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        return jsonify({"error": "Invalid email or password"}), 401

    token = generate_token(user["id"], user["username"])
    return jsonify({"token": token, "username": user["username"]}), 200


# ---------------------------------------------------------------------------
# Links Routes
# ---------------------------------------------------------------------------

@app.route("/api/links", methods=["POST"])
@require_auth
def create_link():
    data = request.get_json(force=True)
    original_url = (data.get("url") or "").strip()
    custom_alias = (data.get("alias") or "").strip()
    title = (data.get("title") or "").strip()

    if not original_url:
        return jsonify({"error": "URL is required"}), 400

    # Add scheme if missing
    if not original_url.startswith(("http://", "https://")):
        original_url = "https://" + original_url

    if not is_valid_url(original_url):
        return jsonify({"error": "Invalid URL format"}), 400

    db = get_db()
    user_id = g.current_user["user_id"]

    # Determine short code
    if custom_alias:
        # Validate alias
        if not re.match(r"^[a-zA-Z0-9_-]{3,20}$", custom_alias):
            return jsonify({"error": "Alias must be 3–20 alphanumeric chars, hyphens, or underscores"}), 400
        existing = db.execute("SELECT id FROM links WHERE short_code = ?", (custom_alias,)).fetchone()
        if existing:
            return jsonify({"error": "That alias is already taken"}), 409
        short_code = custom_alias
    else:
        short_code = generate_short_code()

    cur = db.execute(
        "INSERT INTO links (user_id, original_url, short_code, title) VALUES (?, ?, ?, ?)",
        (user_id, original_url, short_code, title or None),
    )
    db.commit()

    link = db.execute("SELECT * FROM links WHERE id = ?", (cur.lastrowid,)).fetchone()
    return jsonify({
        "id": link["id"],
        "original_url": link["original_url"],
        "short_code": link["short_code"],
        "short_url": f"{BASE_URL}/{link['short_code']}",
        "title": link["title"],
        "click_count": link["click_count"],
        "created_at": link["created_at"],
    }), 201


@app.route("/api/links", methods=["GET"])
@require_auth
def get_links():
    db = get_db()
    user_id = g.current_user["user_id"]
    rows = db.execute(
        "SELECT * FROM links WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()
    links = [
        {
            "id": r["id"],
            "original_url": r["original_url"],
            "short_code": r["short_code"],
            "short_url": f"{BASE_URL}/{r['short_code']}",
            "title": r["title"],
            "click_count": r["click_count"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]
    return jsonify(links), 200


@app.route("/api/links/<int:link_id>", methods=["DELETE"])
@require_auth
def delete_link(link_id):
    db = get_db()
    user_id = g.current_user["user_id"]
    link = db.execute(
        "SELECT id FROM links WHERE id = ? AND user_id = ?", (link_id, user_id)
    ).fetchone()
    if not link:
        return jsonify({"error": "Link not found"}), 404

    db.execute("DELETE FROM clicks WHERE link_id = ?", (link_id,))
    db.execute("DELETE FROM links WHERE id = ?", (link_id,))
    db.commit()
    return jsonify({"message": "Deleted"}), 200


@app.route("/api/links/<int:link_id>/stats", methods=["GET"])
@require_auth
def get_stats(link_id):
    db = get_db()
    user_id = g.current_user["user_id"]
    link = db.execute(
        "SELECT * FROM links WHERE id = ? AND user_id = ?", (link_id, user_id)
    ).fetchone()
    if not link:
        return jsonify({"error": "Link not found"}), 404

    # Clicks per day (last 30 days)
    daily = db.execute("""
        SELECT DATE(clicked_at) as day, COUNT(*) as count
        FROM clicks
        WHERE link_id = ?
          AND clicked_at >= datetime('now', '-30 days')
        GROUP BY DATE(clicked_at)
        ORDER BY day
    """, (link_id,)).fetchall()

    # Recent clicks
    recent = db.execute("""
        SELECT clicked_at, referrer, user_agent
        FROM clicks
        WHERE link_id = ?
        ORDER BY clicked_at DESC
        LIMIT 10
    """, (link_id,)).fetchall()

    return jsonify({
        "id": link["id"],
        "original_url": link["original_url"],
        "short_code": link["short_code"],
        "short_url": f"{BASE_URL}/{link['short_code']}",
        "title": link["title"],
        "click_count": link["click_count"],
        "created_at": link["created_at"],
        "daily_clicks": [{"day": r["day"], "count": r["count"]} for r in daily],
        "recent_clicks": [
            {
                "clicked_at": r["clicked_at"],
                "referrer": r["referrer"],
                "user_agent": r["user_agent"],
            }
            for r in recent
        ],
    }), 200


# ---------------------------------------------------------------------------
# Redirect Route
# ---------------------------------------------------------------------------

@app.route("/<code>")
def redirect_short(code):
    # Skip API and static routes
    if code in ("api", "favicon.ico", "static"):
        return jsonify({"error": "Not found"}), 404

    db = get_db()
    link = db.execute("SELECT * FROM links WHERE short_code = ?", (code,)).fetchone()
    if not link:
        # Redirect to home with error
        return redirect("/?error=not-found")

    # Record click
    db.execute(
        "INSERT INTO clicks (link_id, referrer, user_agent) VALUES (?, ?, ?)",
        (link["id"], request.referrer or "", request.headers.get("User-Agent", "")),
    )
    db.execute("UPDATE links SET click_count = click_count + 1 WHERE id = ?", (link["id"],))
    db.commit()

    return redirect(link["original_url"], code=302)


# ---------------------------------------------------------------------------
# Serve Frontend
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    print("=" * 50)
    print("  URL Shortener running at http://localhost:5000")
    print("=" * 50)
    app.run(debug=True, port=5000)
