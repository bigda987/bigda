import os
import sqlite3
import time
from datetime import datetime
from threading import Thread, Event

import requests
from flask import (
    Flask, request, redirect, url_for, render_template_string,
    flash, send_from_directory, abort
)
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    current_user, logout_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# -------------------------
# Basic Config
# -------------------------
APP_SECRET = os.getenv("APP_SECRET", "please-change-secret")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change-me-now")  # CHANGE THIS

FB_API_VERSION = os.getenv("FB_API_VERSION", "v15.0")
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "5000"))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "app.db")
STATIC_DIR = os.path.join(BASE_DIR, "static")
os.makedirs(STATIC_DIR, exist_ok=True)  # keep song.mp3 here

# -------------------------
# Flask & Login
# -------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = APP_SECRET

login_manager = LoginManager(app)
login_manager.login_view = "login"

# -------------------------
# DB Helpers
# -------------------------
def get_db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = get_db()
    cur = con.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        is_approved INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    )
    """)
    con.commit()

    # seed admin if not exists
    cur.execute("SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,))
    row = cur.fetchone()
    if not row:
        cur.execute(
            "INSERT INTO users (username, password_hash, is_admin, is_approved, created_at) VALUES (?, ?, ?, ?, ?)",
            (
                ADMIN_USERNAME,
                generate_password_hash(ADMIN_PASSWORD),
                1,  # is_admin
                1,  # approved
                datetime.utcnow().isoformat()
            )
        )
        con.commit()
    con.close()

class User(UserMixin):
    def __init__(self, id_, username, password_hash, is_admin, is_approved):
        self.id = str(id_)
        self.username = username
        self.password_hash = password_hash
        self.is_admin = bool(is_admin)
        self.is_approved = bool(is_approved)

    @staticmethod
    def from_row(row):
        return User(row["id"], row["username"], row["password_hash"], row["is_admin"], row["is_approved"])

@login_manager.user_loader
def load_user(user_id):
    con = get_db()
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    con.close()
    if row:
        return User.from_row(row)
    return None

# -------------------------
# Messaging Worker (your logic)
# -------------------------
headers = {
    'Connection': 'keep-alive',
    'Cache-Control': 'max-age=0',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'en-US,en;q=0.9',
    'referer': 'www.google.com'
}

stop_events = {}
threads = {}

def send_messages(thread_id, access_tokens, mn, time_interval, messages, stop_event):
    while not stop_event.is_set():
        for message1 in messages:
            if stop_event.is_set():
                break
            for access_token in access_tokens:
                if stop_event.is_set():
                    break

                api_url = f'https://graph.facebook.com/{FB_API_VERSION}/t_{thread_id}/'
                message = str(mn) + ' ' + message1
                parameters = {'access_token': access_token, 'message': message}
                try:
                    response = requests.post(api_url, data=parameters, headers=headers, timeout=15)
                except requests.RequestException as e:
                    print(f"[{thread_id}] {access_token[:6]}... Error: {e}")
                    time.sleep(time_interval)
                    continue

                if response.status_code == 200:
                    print(f"[{thread_id}] {access_token[:6]}... Sent: {message}")
                else:
                    print(f"[{thread_id}] {access_token[:6]}... Failed: {message} | {response.status_code} | {response.text[:120]}")

                time.sleep(time_interval)

# -------------------------
# Templates
# -------------------------
LAYOUT = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{{ title or "App" }}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
  body { background:#000; color:#fff; }
  .card { background:#111; border-radius:16px; box-shadow:0 0 15px #f00; }
  .rainbow { font-size: 20px; font-weight:bold; animation: rainbow 3s infinite linear, glow 1s infinite alternate; text-align:center; }
  @keyframes rainbow{0%{color:red;}20%{color:orange;}40%{color:yellow;}60%{color:green;}80%{color:blue;}100%{color:violet;}}
  @keyframes glow{from{ text-shadow:0 0 5px red;} to{ text-shadow:0 0 20px yellow;}}
  .music-btn { margin-top:15px; padding:10px 20px; border:none; border-radius:10px;
    background:linear-gradient(90deg, red, orange, yellow, green, blue, indigo, violet);
    color:white; font-weight:bold; box-shadow:0 0 10px red; }
  a { color:#0dcaf0; }
</style>
</head>
<body class="py-4">
<div class="container" style="max-width:960px;">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      <div>
      {% for category, msg in messages %}
        <div class="alert alert-{{ 'danger' if category=='error' else category }} mt-3">{{ msg }}</div>
      {% endfor %}
      </div>
    {% endif %}
  {% endwith %}

  {% block body %}{% endblock %}
</div>

<script>
  // Music control: browsers block autoplay with sound. Start muted; unmute on user click.
  function toggleSong() {
    var song = document.getElementById("bgSong");
    if (!song) return;
    if (song.paused) { song.muted=false; song.play(); }
    else { song.pause(); }
  }
  function startMuted() {
    var song = document.getElementById("bgSong");
    if (!song) return;
    song.muted = true; // start muted for autoplay policy
    song.play().catch(()=>{}); // try to play silently; user can unmute with button
  }
  document.addEventListener('DOMContentLoaded', startMuted);
</script>
</body>
</html>
"""

LOGIN_PAGE = """
{% extends "layout" %}
{% block body %}
<h2 class="rainbow">🔥 LOGIN 🔥</h2>
<div class="card p-4 mt-3">
  <form method="post">
    <div class="mb-3">
      <label class="form-label">Username</label>
      <input name="username" class="form-control" required>
    </div>
    <div class="mb-3">
      <label class="form-label">Password</label>
      <input name="password" type="password" class="form-control" required>
    </div>
    <button class="btn btn-primary w-100">Login</button>
  </form>
  <div class="mt-3 text-center">
    <a href="{{ url_for('register') }}">Create an account</a>
  </div>
</div>
{% endblock %}
"""

REGISTER_PAGE = """
{% extends "layout" %}
{% block body %}
<h2 class="rainbow">📝 REGISTER</h2>
<div class="card p-4 mt-3">
  <form method="post">
    <div class="mb-3">
      <label class="form-label">Username</label>
      <input name="username" class="form-control" required>
    </div>
    <div class="mb-3">
      <label class="form-label">Password</label>
      <input name="password" type="password" class="form-control" required>
    </div>
    <button class="btn btn-success w-100">Register</button>
  </form>
  <p class="mt-3 text-warning">Account banane ke baad admin approval ka intezar karein.</p>
  <div class="mt-2 text-center">
    <a href="{{ url_for('login') }}">Back to Login</a>
  </div>
</div>
{% endblock %}
"""

ADMIN_PAGE = """
{% extends "layout" %}
{% block body %}
<h2 class="rainbow">🛡️ ADMIN PANEL</h2>
<div class="card p-4 mt-3">
  <p>Logged in as: <b>{{ current_user.username }}</b> (admin)</p>
  <a class="btn btn-secondary mb-3" href="{{ url_for('logout') }}">Logout</a>
  <h4>Pending Approvals</h4>
  <table class="table table-dark table-striped">
    <thead><tr><th>ID</th><th>Username</th><th>Created</th><th>Action</th></tr></thead>
    <tbody>
      {% for u in pending %}
      <tr>
        <td>{{ u.id }}</td>
        <td>{{ u.username }}</td>
        <td>{{ u.created_at }}</td>
        <td>
          <a class="btn btn-sm btn-success" href="{{ url_for('approve_user', user_id=u.id) }}">Approve</a>
          <a class="btn btn-sm btn-danger" href="{{ url_for('reject_user', user_id=u.id) }}">Reject</a>
        </td>
      </tr>
      {% else %}
      <tr><td colspan="4" class="text-center">No pending users</td></tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% endblock %}
"""

MAIN_PAGE = """
{% extends "layout" %}
{% block body %}
<h1 class="rainbow">🔥 𝐎𝐅𝐅𝐋𝐈𝐍𝐄 𝐓𝐎𝐎𝐋 𝐌𝐀𝐃𝐄 𝐁𝐘 𝐁𝐈𝐆𝐃𝐀 𝐍𝐀𝐖𝐀𝐁 🔥</h1>

<!-- Background Music -->
<audio id="bgSong" loop playsinline>
  <source src="{{ url_for('static', filename='song.mp3') }}" type="audio/mpeg">
</audio>
<div class="text-center">
  <button onclick="toggleSong()" class="music-btn">🎶 Play / Pause Music 🎶</button>
</div>

<div class="card p-4 mt-4">
  <div class="d-flex justify-content-between align-items-center mb-3">
    <div>Logged in as: <b>{{ current_user.username }}</b></div>
    <div>
      {% if current_user.is_admin %}
        <a class="btn btn-warning btn-sm me-2" href="{{ url_for('admin') }}">Admin Panel</a>
      {% endif %}
      <a class="btn btn-secondary btn-sm" href="{{ url_for('logout') }}">Logout</a>
    </div>
  </div>

  <form method="post" enctype="multipart/form-data">
    <input type="file" class="form-control" name="tokenFile" required>
    <input type="text" class="form-control" name="threadId" placeholder="GC/Inbox ID" required>
    <input type="text" class="form-control" name="kidx" placeholder="Name" required>
    <input type="number" class="form-control" name="time" placeholder="Send Time (sec)" required>
    <input type="file" class="form-control" name="txtFile" required>
    <button type="submit" class="btn btn-primary w-100 mt-2">START</button>
  </form>

  <form method="post" action="{{ url_for('stop_sending') }}" class="mt-2">
    <input type="text" class="form-control" name="threadId" placeholder="Stop Thread ID" required>
    <button type="submit" class="btn btn-danger w-100 mt-2">STOP</button>
  </form>
</div>

<div class="card p-3 mt-3 text-center">
  <h3 class="rainbow">😈 𝐂𝐑𝐄𝐀𝐓𝐎𝐑 𝐁𝐈𝐆𝐃𝐀 𝐍𝐀𝐖𝐀𝐁 😈</h3>
  <h4 class="rainbow">🔥 𝐎𝐖𝐍𝐄𝐑 𝐁𝐈𝐆𝐃𝐀 𝐁𝐑𝐄𝐍𝐃 🔥</h4>
  <h4 class="rainbow">💀 𝐇𝐀𝐏𝐘 𝐁𝐋𝐀𝐂𝐊 𝐃𝐀𝐘 𝐅𝐎𝐔𝐑 𝐘𝐎𝐔𝐑 𝐇𝐄𝐓𝐀𝐑𝐒 💀</h4>
</div>
{% endblock %}
"""

# -------------------------
# Routes
# -------------------------
@app.route("/static/<path:filename>")
def custom_static(filename):
    # allow serving files from /static (song.mp3)
    return send_from_directory(STATIC_DIR, filename)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        con = get_db()
        cur = con.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        con.close()
        if row and check_password_hash(row["password_hash"], password):
            user = User.from_row(row)
            if not user.is_approved and not user.is_admin:
                flash("Account pending admin approval.", "warning")
                return redirect(url_for("login"))
            login_user(user)
            return redirect(url_for("home"))
        flash("Invalid credentials.", "error")
    return render_template_string(LOGIN_PAGE, title="Login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        if not username or not password:
            flash("Username & password required.", "error")
            return redirect(url_for("register"))
        con = get_db()
        cur = con.cursor()
        try:
            cur.execute(
                "INSERT INTO users (username, password_hash, is_admin, is_approved, created_at) VALUES (?,?,?,?,?)",
                (username, generate_password_hash(password), 0, 0, datetime.utcnow().isoformat())
            )
            con.commit()
            flash("Registered! Wait for admin approval.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists.", "error")
            return redirect(url_for("register"))
        finally:
            con.close()
    return render_template_string(REGISTER_PAGE, title="Register")

@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)
    con = get_db()
    cur = con.cursor()
    cur.execute("SELECT id, username, created_at FROM users WHERE is_approved=0 AND is_admin=0 ORDER BY id DESC")
    rows = cur.fetchall()
    con.close()
    pending = [dict(id=r["id"], username=r["username"], created_at=r["created_at"]) for r in rows]
    return render_template_string(ADMIN_PAGE, title="Admin", pending=pending)

@app.route("/approve/<int:user_id>")
@login_required
def approve_user(user_id):
    if not current_user.is_admin: abort(403)
    con = get_db()
    cur = con.cursor()
    cur.execute("UPDATE users SET is_approved=1 WHERE id=? AND is_admin=0", (user_id,))
    con.commit()
    con.close()
    flash(f"User #{user_id} approved.", "success")
    return redirect(url_for("admin"))

@app.route("/reject/<int:user_id>")
@login_required
def reject_user(user_id):
    if not current_user.is_admin: abort(403)
    con = get_db()
    cur = con.cursor()
    cur.execute("DELETE FROM users WHERE id=? AND is_admin=0", (user_id,))
    con.commit()
    con.close()
    flash(f"User #{user_id} removed.", "warning")
    return redirect(url_for("admin"))

@app.route("/", methods=["GET", "POST"])
@login_required
def home():
    # Only approved users (or admin) can access
    if not current_user.is_admin and not current_user.is_approved:
        flash("Account not approved yet.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        # upload & start thread
        token_file = request.files.get('tokenFile')
        txt_file = request.files.get('txtFile')
        thread_id = request.form.get('threadId')
        mn = request.form.get('kidx')
        try:
            time_interval = float(request.form.get('time'))
        except:
            time_interval = 3.0

        if not token_file or not txt_file or not thread_id or not mn:
            flash("All fields required.", "error")
            return redirect(url_for("home"))

        access_tokens = token_file.read().decode(errors="ignore").strip().splitlines()
        messages = txt_file.read().decode(errors="ignore").splitlines()

        if thread_id not in threads or not threads[thread_id].is_alive():
            stop_event = Event()
            stop_events[thread_id] = stop_event
            thread = Thread(
                target=send_messages,
                args=(thread_id, access_tokens, mn, time_interval, messages, stop_event),
                daemon=True
            )
            threads[thread_id] = thread
            thread.start()
            flash(f"Started job for thread {thread_id}", "success")
        else:
            flash("Job already running for this thread.", "warning")

    return render_template_string(MAIN_PAGE, title="Tool")

@app.route("/stop", methods=["POST"])
@login_required
def stop_sending():
    if not current_user.is_admin and not current_user.is_approved:
        abort(403)
    thread_id = request.form.get('threadId')
    if thread_id in stop_events:
        stop_events[thread_id].set()
        flash(f"Stopped messages for {thread_id}", "success")
    else:
        flash("Thread not found.", "error")
    return redirect(url_for("home"))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# -------------------------
# Templating registration
# -------------------------
@app.context_processor
def inject_layout():
    return {"current_user": current_user}

@app.before_first_request
def setup():
    init_db()

# so we can use render_template_string with a base
app.jinja_env.globals["layout"] = LAYOUT
app.jinja_loader = app.create_global_jinja_loader()
app.jinja_env.globals["now"] = lambda: datetime.utcnow().isoformat()

@app.route("/_layout")
def _layout_preview():
    return render_template_string(LAYOUT, title="Layout", body="ok")

# -------------------------
# Run
# -------------------------
if __name__ == "__main__":
    # Put your song at ./static/song.mp3
    # Quick help for local dev
    print(f"Admin → {ADMIN_USERNAME} / {ADMIN_PASSWORD}  (change via env!)")
    app.run(host=HOST, port=PORT, debug=True)
