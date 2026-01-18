from __future__ import annotations

import os
import sqlite3
from datetime import timedelta
from functools import wraps

from flask import Flask, Response, g, redirect, request, session, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash

# =========================
# Config
# =========================
APP_SECRET = os.environ.get("APP_SECRET_KEY", "CHANGE_ME__PLEASE_SET_ENV_APP_SECRET_KEY")
DB_PATH = os.environ.get("APP_DB_PATH", os.path.join(os.path.dirname(__file__), "auth.db"))

app = Flask(__name__)
app.secret_key = APP_SECRET
app.permanent_session_lifetime = timedelta(days=7)


# =========================
# DB
# =========================
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','user')),
            display_name TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    db.commit()

    def ensure_user(username: str, password: str, role: str, display_name: str):
        row = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if row is None:
            db.execute(
                "INSERT INTO users(username,password,role,display_name) VALUES(?,?,?,?)",
                (username, password, role, display_name),
            )
            db.commit()

    ensure_user("admin", os.environ.get("DEFAULT_ADMIN_PASSWORD", "admin123"), "admin", "Quản Trị Viên")
    ensure_user("user", os.environ.get("DEFAULT_USER_PASSWORD", "user123"), "user", "Người Dùng")


@app.before_request
def _ensure_db():
    init_db()


# =========================
# Auth helpers
# =========================
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "uid" not in session:
            nxt = request.path or "/"
            return redirect(f"/login?next={nxt}")
        return fn(*args, **kwargs)

    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "uid" not in session:
            nxt = request.path or "/"
            return redirect(f"/login?next={nxt}")
        if session.get("role") != "admin":
            return Response("Forbidden", status=403)
        return fn(*args, **kwargs)

    return wrapper


def current_user():
    if "uid" not in session:
        return None
    db = get_db()
    return db.execute("SELECT id, username, role, display_name FROM users WHERE id=?", (session["uid"],)).fetchone()


# =========================
# PWA routes
# =========================
@app.route('/manifest.json')
def manifest():
    return Response('''{
  "name": "TimeMark - Chân Thực",
  "short_name": "TimeMark",
  "description": "Ghép ảnh với dấu thời gian chân thực",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#07101f",
  "theme_color": "#66a6ff",
  "orientation": "portrait",
  "icons": [
    {
      "src": "/icon.png",
      "sizes": "512x512",
      "type": "image/png",
      "purpose": "any maskable"
    }
  ]
}''', mimetype='application/json')


@app.route('/icon.png')
def serve_icon():
    return send_from_directory('.', 'icon.png')


@app.route('/sw.js')
def service_worker():
    return Response('''
self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open('timemark-v1').then((cache) => cache.addAll([
      '/',
      '/icon.png'
    ]))
  );
});

self.addEventListener('fetch', (e) => {
  e.respondWith(
    caches.match(e.request).then((response) => response || fetch(e.request))
  );
});
''', mimetype='application/javascript')


# =========================
# UI
# =========================
FONT_LINKS = r"""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
"""

BASE_CSS = r"""
<style>
  :root{
    --bg: linear-gradient(135deg, #0a1628 0%, #162541 100%);
    --card: rgba(255,255,255,.06);
    --card-hover: rgba(255,255,255,.08);
    --fg:#f0f4f9;
    --muted:#8fa3bf;
    --accent:#5b9eff;
    --accent-hover:#4a8ee8;
    --ok:#2dd4bf;
    --ok-hover:#26bca7;
    --danger:#ef4444;
    --danger-hover:#dc2626;
    --border: rgba(255,255,255,.1);
    --shadow: rgba(0,0,0,.3);
  }
  
  *{ box-sizing:border-box; margin:0; padding:0; }
  
  body{ 
    background: var(--bg); 
    color: var(--fg); 
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    line-height: 1.6;
    min-height: 100vh;
    overflow-x: hidden;
  }
  
  a{ color: var(--accent); text-decoration:none; transition: all .2s; }
  a:hover{ color: var(--accent-hover); }
  
  /* Header */
  header{
    padding: 16px 20px;
    background: rgba(10,22,40,.95);
    backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
    position: sticky;
    top: 0;
    z-index: 100;
    box-shadow: 0 4px 20px var(--shadow);
  }
  
  header h1{ 
    font-size: 18px;
    font-weight: 800;
    color: var(--fg);
    display: flex;
    align-items: center;
    gap: 10px;
  }
  
  .logo{ width: 32px; height: 32px; border-radius: 8px; }
  
  .badge{ 
    display: inline-flex;
    padding: 6px 14px;
    border-radius: 20px;
    border: 1px solid var(--border);
    font-size: 13px;
    font-weight: 500;
    color: var(--fg);
    background: var(--card);
    transition: all .2s;
    white-space: nowrap;
  }
  
  .badge:hover{
    background: var(--card-hover);
    border-color: var(--accent);
    transform: translateY(-1px);
  }
  
  /* Layout */
  .wrap{ 
    display: grid;
    grid-template-columns: 400px 1fr;
    gap: 20px;
    padding: 20px;
    max-width: 1800px;
    margin: 0 auto;
  }
  
  .panel{ 
    background: var(--card);
    backdrop-filter: blur(12px);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 24px;
    height: fit-content;
    position: sticky;
    top: 90px;
    box-shadow: 0 8px 32px var(--shadow);
  }
  
  .panel h2{ 
    margin: 0 0 16px 0;
    font-size: 15px;
    font-weight: 700;
    color: var(--fg);
    display: flex;
    align-items: center;
    gap: 8px;
  }
  
  .section-divider{
    height: 1px;
    background: var(--border);
    margin: 24px 0;
  }
  
  /* Form elements */
  label{ 
    display: block;
    font-size: 13px;
    font-weight: 500;
    color: var(--muted);
    margin: 14px 0 8px;
  }
  
  input[type="text"], 
  input[type="password"], 
  input[type="time"], 
  input[type="date"], 
  input[type="file"],
  select{
    width: 100%;
    padding: 12px 14px;
    border-radius: 12px;
    border: 1px solid var(--border);
    background: rgba(0,0,0,.3);
    color: var(--fg);
    outline: none;
    font-size: 14px;
    transition: all .2s;
    font-family: inherit;
  }
  
  input:focus, select:focus{
    border-color: var(--accent);
    background: rgba(0,0,0,.4);
    box-shadow: 0 0 0 3px rgba(91,158,255,.1);
  }
  
  .row{ 
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }
  
  /* Buttons */
  .btns{ 
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    margin-top: 16px;
  }
  
  button{
    border: 0;
    border-radius: 12px;
    padding: 12px 20px;
    cursor: pointer;
    font-weight: 600;
    font-size: 14px;
    color: #fff;
    background: var(--accent);
    transition: all .2s;
    font-family: inherit;
    box-shadow: 0 4px 12px rgba(91,158,255,.3);
  }
  
  button:hover{
    background: var(--accent-hover);
    transform: translateY(-2px);
    box-shadow: 0 6px 16px rgba(91,158,255,.4);
  }
  
  button:active{
    transform: translateY(0);
  }
  
  button.secondary{ 
    background: var(--card);
    color: var(--fg);
    border: 1px solid var(--border);
    box-shadow: none;
  }
  
  button.secondary:hover{
    background: var(--card-hover);
    border-color: var(--accent);
    box-shadow: 0 4px 12px rgba(91,158,255,.2);
  }
  
  button.ok{ 
    background: var(--ok);
    color: #0a1628;
    box-shadow: 0 4px 12px rgba(45,212,191,.3);
  }
  
  button.ok:hover{
    background: var(--ok-hover);
    box-shadow: 0 6px 16px rgba(45,212,191,.4);
  }
  
  button.danger{ 
    background: var(--danger);
    color: #fff;
    box-shadow: 0 4px 12px rgba(239,68,68,.3);
  }
  
  button.danger:hover{
    background: var(--danger-hover);
    box-shadow: 0 6px 16px rgba(239,68,68,.4);
  }
  
  /* Info box */
  .hint{ 
    font-size: 13px;
    color: var(--muted);
    margin-top: 12px;
    line-height: 1.5;
    padding: 12px;
    background: rgba(91,158,255,.08);
    border-radius: 8px;
    border-left: 3px solid var(--accent);
  }
  
  /* Canvas stage */
  .stage{
    background: rgba(0,0,0,.25);
    border: 2px dashed var(--border);
    border-radius: 16px;
    padding: 20px;
    min-height: 70vh;
    display: flex;
    align-items: center;
    justify-content: center;
    overflow: auto;
  }
  
  canvas{ 
    max-width: 100%;
    height: auto;
    border-radius: 12px;
    background: #000;
    box-shadow: 0 12px 48px rgba(0,0,0,.5);
  }
  
  /* Toolbox */
  .toolbox{ 
    margin-top: 12px;
    padding: 16px;
    border-radius: 12px;
    border: 1px solid var(--border);
    background: rgba(0,0,0,.2);
  }
  
  .inline{ 
    display: flex;
    gap: 12px;
    align-items: center;
  }
  
  .inline input[type="range"]{ 
    flex: 1;
    accent-color: var(--accent);
  }
  
  /* Auth pages */
  .center{ 
    max-width: 440px;
    margin: 60px auto;
    padding: 0 20px;
  }
  
  .card{ 
    background: var(--card);
    backdrop-filter: blur(12px);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 32px;
    box-shadow: 0 12px 48px var(--shadow);
  }
  
  .card h2{
    margin: 0 0 8px 0;
    font-size: 24px;
    font-weight: 800;
  }
  
  .msg{ 
    margin-top: 16px;
    padding: 14px;
    border-radius: 12px;
    border: 1px solid var(--border);
    background: rgba(91,158,255,.1);
    font-size: 13px;
    color: var(--fg);
  }
  
  /* Table */
  table{ 
    width: 100%;
    border-collapse: collapse;
    margin-top: 16px;
  }
  
  th, td{ 
    text-align: left;
    font-size: 13px;
    padding: 14px 12px;
    border-bottom: 1px solid var(--border);
  }
  
  th{ 
    color: var(--fg);
    font-weight: 600;
    background: rgba(255,255,255,.03);
  }
  
  tr:hover{
    background: rgba(255,255,255,.02);
  }
  
  /* Camera modal */
  .modal{ 
    display: none;
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0,0,0,.95);
    backdrop-filter: blur(8px);
    z-index: 9999;
    align-items: center;
    justify-content: center;
    animation: fadeIn .3s;
  }
  
  .modal.active{ display: flex; }
  
  .modal-content{ 
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 28px;
    max-width: 90%;
    max-height: 90%;
    overflow: auto;
    box-shadow: 0 20px 80px rgba(0,0,0,.6);
  }
  
  video{ 
    max-width: 100%;
    border-radius: 12px;
    background: #000;
    margin-bottom: 16px;
  }
  
  @keyframes fadeIn{
    from{ opacity: 0; }
    to{ opacity: 1; }
  }
  
  /* Password visibility toggle */
  .password-field{
    position: relative;
  }
  
  .password-field input{
    padding-right: 45px;
  }
  
  .toggle-password{
    position: absolute;
    right: 12px;
    top: 50%;
    transform: translateY(-50%);
    background: none;
    border: none;
    padding: 6px;
    cursor: pointer;
    font-size: 18px;
    opacity: 0.6;
    transition: opacity .2s;
    box-shadow: none !important;
  }
  
  .toggle-password:hover{
    opacity: 1;
    transform: translateY(-50%);
  }
  
  /* Responsive */
  @media (max-width: 1024px) {
    .wrap{ 
      grid-template-columns: 1fr;
      padding: 16px;
    }
    
    .panel{ 
      position: static;
    }
  }
  
  @media (max-width: 640px) {
    header{ padding: 12px 16px; }
    header h1{ font-size: 16px; }
    .logo{ width: 28px; height: 28px; }
    .badge{ padding: 4px 10px; font-size: 12px; }
    .panel{ padding: 20px; }
    .card{ padding: 24px; }
    .row{ grid-template-columns: 1fr; }
  }
</style>
"""


def render_page(title: str, body_html: str, user_row=None) -> str:
    right_html = ""
    if user_row is not None:
        display = user_row.get("display_name") or user_row["username"]
        right_html = (
            f'<span class="badge">{display} · {user_row["role"]}</span>'
            ' <a class="badge" href="/logout">Đăng xuất</a>'
        )
        if user_row["role"] == "admin":
            right_html += ' <a class="badge" href="/admin">⚙️ Quản lý</a>'

    pwa_meta = """
    <link rel="manifest" href="/manifest.json">
    <meta name="theme-color" content="#66a6ff">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <link rel="apple-touch-icon" href="/icon.png">
    <script>
      if('serviceWorker' in navigator){
        navigator.serviceWorker.register('/sw.js');
      }
    </script>
    """

    return (
        "<!doctype html><html lang='vi'><head>"
        "<meta charset='utf-8'/>"
        "<meta name='viewport' content='width=device-width,initial-scale=1,maximum-scale=1'/>"
        f"<title>{title}</title>"
        f"{pwa_meta}"
        f"{FONT_LINKS}{BASE_CSS}"
        "</head><body>"
        "<header>"
        f"<h1><img src='/icon.png' class='logo' alt='TimeMark'/>{title}</h1>"
        f"<div style='display:flex; gap:8px; align-items:center; flex-wrap:wrap'>{right_html}</div>"
        "</header>"
        f"{body_html}"
        "</body></html>"
    )


# =========================
# Login / Logout
# =========================
@app.get("/login")
def login():
    msg = request.args.get("msg", "")
    nxt = request.args.get("next", "/")
    body = (
        "<div class='center'><div class='card'>"
        "<h2>🔐 Đăng nhập</h2>"
        "<p style='color:var(--muted); margin-bottom:24px;'>Đăng nhập để sử dụng TimeMark</p>"
        "<form method='post' action='/login'>"
        f"<input type='hidden' name='next' value='{nxt}'>"
        "<label>Tên đăng nhập</label>"
        "<input name='username' type='text' autocomplete='username' placeholder='admin' required>"
        "<label>Mật khẩu</label>"
        "<div class='password-field'>"
        "<input id='loginPass' name='password' type='password' autocomplete='current-password' placeholder='••••••••' required>"
        "<button type='button' class='toggle-password' onclick='togglePassword(\"loginPass\")'>👁️</button>"
        "</div>"
        "<div class='btns'><button class='ok' type='submit'>Đăng nhập</button></div>"
        "<div class='hint'>💡 <b>Mặc định:</b> admin/admin123 hoặc user/user123</div>"
        + (f"<div class='msg'>{msg}</div>" if msg else "")
        + "</form></div></div>"
        "<script>"
        "function togglePassword(id){"
        "const inp=document.getElementById(id);"
        "const btn=event.target;"
        "if(inp.type==='password'){inp.type='text';btn.textContent='🙈';}else{inp.type='password';btn.textContent='👁️';}"
        "}"
        "</script>"
    )
    return Response(render_page("Đăng nhập", body), mimetype="text/html; charset=utf-8")


@app.post("/login")
def login_post():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    nxt = request.form.get("next") or "/"

    db = get_db()
    row = db.execute(
        "SELECT id, username, password, role, display_name FROM users WHERE username=?",
        (username,),
    ).fetchone()

    if row is None or row["password"] != password:
        return redirect(f"/login?msg=❌+Sai+tên+đăng+nhập+hoặc+mật+khẩu&next={nxt}")

    session.permanent = True
    session["uid"] = int(row["id"])
    session["username"] = row["username"]
    session["role"] = row["role"]
    return redirect(nxt)


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login?msg=✅+Đã+đăng+xuất+thành+công")


# =========================
# Main app - TIẾP THEO PHẦN 2
# =========================

# Phần còn lại của INDEX_HTML và các route

INDEX_HTML = r"""
<div class="wrap">
  <div class="panel">
    <h2>📷 1. Chọn ảnh</h2>
    <label>Chọn ảnh từ thư viện</label>
    <input id="file" type="file" accept="image/*" />
    <div class="btns">
      <button class="secondary" id="openCamera">📸 Chụp ảnh ngay</button>
    </div>
    <div class="section-divider"></div>
    <h2>⏰ 2. Chỉnh giờ & ngày</h2>
    <div class="row">
      <div><label>Giờ</label><input id="time" type="time" value="05:37" /></div>
      <div><label>Ngày</label><input id="date" type="date" /></div>
    </div>
    <div class="row">
      <div><label>Thứ</label>
        <select id="dow">
          <option value="Chủ Nhật">Chủ Nhật</option>
          <option value="Thứ Hai">Thứ Hai</option>
          <option value="Thứ Ba">Thứ Ba</option>
          <option value="Thứ Tư">Thứ Tư</option>
          <option value="Thứ Năm" selected>Thứ Năm</option>
          <option value="Thứ Sáu">Thứ Sáu</option>
          <option value="Thứ Bảy">Thứ Bảy</option>
        </select>
      </div>
    </div>
    <label>Địa chỉ (cố định)</label>
    <input type="text" value="268B Võ Nguyên Giáp, Bắc Mỹ Phú, Ngũ Hành Sơn, Đà Nẵng 550000" disabled style="font-size:12px;" />
    <div class="hint">✨ Overlay tự động căn chỉnh theo kích thước ảnh<br/>📍 Giờ & ngày luôn rõ ràng, dễ đọc</div>
    <div class="section-divider"></div>
    <h2>🖌️ 3. Xóa chữ cũ</h2>
    <div class="btns">
      <button class="secondary" id="reset">↺ Reset ảnh gốc</button>
      <button class="secondary" id="toggleMask">🎨 Che chữ</button>
      <button class="secondary" id="clearMask">🗑️ Xóa vùng che</button>
    </div>
    <div class="toolbox" id="maskBox" style="display:none;">
      <div class="inline">
        <span style="font-size:13px;color:var(--muted);min-width:100px;font-weight:500;">Cỡ bút</span>
        <input id="brush" type="range" min="10" max="140" value="55" />
        <span class="badge" id="brushVal">55</span>
      </div>
      <div class="hint" style="margin-top:8px;">💡 Tô lên vùng có chữ cũ để làm mờ</div>
    </div>
    <div class="section-divider"></div>
    <h2>✅ 4. Xuất ảnh</h2>
    <div class="btns">
      <button class="ok" id="render">🎯 Ghép overlay</button>
      <button id="download">💾 Tải về</button>
    </div>
    <div class="msg" id="status">📤 Chưa có ảnh</div>
  </div>
  <div class="stage"><canvas id="cv"></canvas></div>
</div>
<div class="modal" id="cameraModal">
  <div class="modal-content">
    <h2 style="margin:0 0 16px 0; font-size:18px; font-weight:700;">📸 Chụp ảnh</h2>
    <video id="video" autoplay playsinline></video>
    <div class="btns">
      <button class="ok" id="capture">✅ Chụp</button>
      <button class="secondary" id="closeCamera">✖️ Đóng</button>
    </div>
  </div>
</div>
<script>
const $ = (id) => document.getElementById(id);
const cv = $("cv"), ctx = cv.getContext("2d"), statusEl = $("status");
let img = new Image(), hasImage = false, originalBitmap = null;
let maskEnabled = false, isPainting = false;
const maskCanvas = document.createElement("canvas"), maskCtx = maskCanvas.getContext("2d");
let stream = null;

function setStatus(t){ statusEl.textContent = t; }
function clamp(n, lo, hi){ return Math.max(lo, Math.min(hi, n)); }
function fitCanvasToImage(w,h){ cv.width = w; cv.height = h; maskCanvas.width = w; maskCanvas.height = h; maskCtx.clearRect(0,0,w,h); }
function formatDateDDMMYYYY(iso){ if(!iso) return ""; const parts = iso.split("-"); if(parts.length !== 3) return ""; return `${parts[2]}/${parts[1]}/${parts[0]}`; }
function fitFontToWidth(ctx, text, fontTemplateFn, startSize, minSize, maxWidth){ let size = startSize; while(size > minSize){ ctx.font = fontTemplateFn(size); if(ctx.measureText(text).width <= maxWidth) return size; size -= 1; } return minSize; }
function maskHasSomething(){ const w = maskCanvas.width, h = maskCanvas.height; if(!w || !h) return false; const d = maskCtx.getImageData(0,0,w,h).data; for(let i=3;i<d.length;i+=4){ if(d[i] > 0) return true; } return false; }

function drawBase(){ ctx.clearRect(0,0,cv.width,cv.height); ctx.drawImage(img, 0, 0, cv.width, cv.height); if(maskHasSomething()){ const w = cv.width, h = cv.height; const small = document.createElement("canvas"); const scale = 0.18; small.width = Math.max(1, Math.floor(w*scale)); small.height = Math.max(1, Math.floor(h*scale)); const sctx = small.getContext("2d"); sctx.imageSmoothingEnabled = true; sctx.drawImage(img,0,0,small.width,small.height); const blur = document.createElement("canvas"); blur.width = w; blur.height = h; const bctx = blur.getContext("2d"); bctx.imageSmoothingEnabled = true; bctx.drawImage(small,0,0,small.width,small.height,0,0,w,h); bctx.globalCompositeOperation = "destination-in"; bctx.drawImage(maskCanvas,0,0); ctx.drawImage(blur,0,0); } }

function drawLeftCluster(ctx, W, H, reservedRight, timeVal, dateText, dowText){ const BASE = Math.min(W,H); const leftMaxWidth = Math.round(W * 0.58); const leftX = clamp(Math.round(W * 0.025), 8, 40); const bottomPad = clamp(Math.round(H * 0.035), 8, 60); const rightLimit = Math.min(leftX + leftMaxWidth, W - reservedRight); const maxWidth = Math.max(140, rightLimit - leftX); const shadowBlur = Math.round(BASE * 0.003); const addr1 = "268B Võ Nguyên Giáp, Bắc Mỹ Phú, Ngũ"; const addr2 = "Hành Sơn, Đà Nẵng 550000"; let addrFont = clamp(Math.round(BASE * 0.038), 11, 32); const addrTpl = (s)=>`400 ${s}px "Inter", -apple-system, sans-serif`; addrFont = fitFontToWidth(ctx, addr1, addrTpl, addrFont, 9, maxWidth); const addrLineH = Math.round(addrFont * 1.2); const addrBlockH = addrLineH * 2; const gapMetaToAddr = clamp(Math.round(BASE * 0.028), 8, 32); let timeFont = clamp(Math.round(BASE * 0.082), 24, 78); const timeTpl = (s)=>`700 ${s}px "Inter", -apple-system, sans-serif`; const minMetaW = Math.round(maxWidth * 0.32); const maxTimeW = Math.max(70, maxWidth - minMetaW); timeFont = fitFontToWidth(ctx, timeVal, timeTpl, timeFont, 16, maxTimeW); const timeScaleY = 1.48; let metaFont = clamp(Math.round(timeFont * 0.38), 9, 34); const metaTpl = (s)=>`500 ${s}px "Inter", -apple-system, sans-serif`; const addrBottomY = H - bottomPad; const timeBaselineY = addrBottomY - addrBlockH - gapMetaToAddr; ctx.save(); ctx.font = timeTpl(timeFont); const timeW = ctx.measureText(timeVal).width; ctx.restore(); const gapX = clamp(Math.round(BASE * 0.016), 7, 20); const lineX = leftX + timeW + gapX; const asc = 0.78; const desc = 0.12; const lineTop = timeBaselineY - Math.round(timeFont * asc * timeScaleY); const lineBottom = timeBaselineY + Math.round(timeFont * desc * timeScaleY); const metaX = lineX + gapX; const metaMaxW = Math.max(70, rightLimit - metaX); const longer = (dateText.length >= dowText.length) ? dateText : dowText; metaFont = fitFontToWidth(ctx, longer, metaTpl, metaFont, 9, metaMaxW); const metaPad = Math.round(metaFont * 0.1); const dateY = lineTop + metaFont + metaPad; const dowY = lineBottom - metaPad; ctx.save(); ctx.textAlign = "left"; ctx.textBaseline = "alphabetic"; ctx.shadowColor = "rgba(0,0,0,0.3)"; ctx.shadowBlur = shadowBlur; ctx.fillStyle = "#FFFFFF"; ctx.font = timeTpl(timeFont); ctx.save(); ctx.scale(1, timeScaleY); ctx.fillText(timeVal, leftX, timeBaselineY / timeScaleY); ctx.restore(); ctx.restore(); ctx.save(); ctx.shadowBlur = 0; ctx.strokeStyle = "#F2B644"; ctx.lineWidth = Math.max(2, Math.round(BASE * 0.0035)); ctx.beginPath(); ctx.moveTo(lineX, lineTop); ctx.lineTo(lineX, lineBottom); ctx.stroke(); ctx.restore(); ctx.save(); ctx.textAlign = "left"; ctx.textBaseline = "alphabetic"; ctx.shadowColor = "rgba(0,0,0,0.3)"; ctx.shadowBlur = shadowBlur; ctx.fillStyle = "#FFFFFF"; ctx.font = metaTpl(metaFont); ctx.fillText(dateText, metaX, dateY); ctx.fillText(dowText, metaX, dowY); ctx.restore(); ctx.save(); ctx.textAlign = "left"; ctx.textBaseline = "bottom"; ctx.shadowColor = "rgba(0,0,0,0.3)"; ctx.shadowBlur = shadowBlur; ctx.fillStyle = "#FFFFFF"; ctx.font = addrTpl(addrFont); ctx.fillText(addr2, leftX, addrBottomY); ctx.fillText(addr1, leftX, addrBottomY - addrLineH); ctx.restore(); }

function drawWatermark(ctx, W, H){ const BASE = Math.min(W,H); const padR = clamp(Math.round(W * 0.018), 8, 36); const padB = clamp(Math.round(H * 0.028), 8, 54); const timePart = "Time"; const markPart = "mark"; const fullText = timePart + markPart; const subText = "100% Chân thực"; let wmFont = clamp(Math.round(BASE * 0.048), 14, 42); let subFont = clamp(Math.round(wmFont * 0.53), 9, 22); const wmTpl = (s)=>`700 ${s}px "Inter", -apple-system, sans-serif`; const subTpl = (s)=>`600 ${s}px "Inter", -apple-system, sans-serif`; const maxWmWidth = Math.round(W * 0.33); wmFont = fitFontToWidth(ctx, fullText, wmTpl, wmFont, 11, maxWmWidth); subFont = clamp(Math.round(wmFont * 0.53), 9, 22); ctx.save(); ctx.font = wmTpl(wmFont); const wmWidth = ctx.measureText(fullText).width; const timeW = ctx.measureText(timePart).width; ctx.restore(); const startX = W - padR - wmWidth; const centerX = startX + wmWidth / 2; const yBottom = H - padB; ctx.save(); ctx.shadowColor = "rgba(0,0,0,0.25)"; ctx.shadowBlur = Math.round(BASE * 0.003); ctx.textBaseline = "bottom"; ctx.textAlign = "center"; ctx.fillStyle = "#E8E8E8"; ctx.font = subTpl(subFont); ctx.fillText(subText, centerX, yBottom); const yTop = yBottom - Math.round(subFont * 1.18); ctx.textAlign = "left"; ctx.font = wmTpl(wmFont); ctx.fillStyle = "#F2B644"; ctx.fillText(timePart, startX, yTop); ctx.fillStyle = "#FFFFFF"; ctx.fillText(markPart, startX + timeW, yTop); ctx.restore(); return padR + Math.round(wmWidth) + clamp(Math.round(W*0.028), 10, 36); }

function drawAllOverlay(){ if(!hasImage) return; drawBase(); const W = cv.width, H = cv.height; const timeVal = $("time").value || "05:37"; const dateText = formatDateDDMMYYYY($("date").value) || "05/01/2026"; const dowText = $("dow").value || "Thứ Năm"; const reservedRight = drawWatermark(ctx, W, H); drawLeftCluster(ctx, W, H, reservedRight, timeVal, dateText, dowText); }

function loadImageFromUrl(url){ img = new Image(); img.onload = ()=>{ fitCanvasToImage(img.naturalWidth, img.naturalHeight); hasImage = true; ctx.drawImage(img,0,0,cv.width,cv.height); originalBitmap = ctx.getImageData(0,0,cv.width,cv.height); if(!$("date").value){ const now = new Date(); $("date").value = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-${String(now.getDate()).padStart(2,'0')}`; } setStatus(`✅ Ảnh: ${img.naturalWidth}×${img.naturalHeight}px`); }; img.src = url; }

$("file").addEventListener("change", (e)=>{ const f = e.target.files && e.target.files[0]; if(!f) return; loadImageFromUrl(URL.createObjectURL(f)); });
$("render").addEventListener("click", ()=>{ if(!hasImage) return alert("⚠️ Bạn chưa chọn ảnh"); drawAllOverlay(); setStatus("✅ Đã ghép overlay thành công!"); });
$("reset").addEventListener("click", ()=>{ if(!hasImage || !originalBitmap) return; ctx.putImageData(originalBitmap, 0, 0); maskCtx.clearRect(0,0,maskCanvas.width,maskCanvas.height); setStatus("↺ Đã reset về ảnh gốc"); });
$("download").addEventListener("click", ()=>{ if(!hasImage) return alert("⚠️ Bạn chưa chọn ảnh"); const a = document.createElement("a"); a.download = `timemark_${Date.now()}.png`; a.href = cv.toDataURL("image/png"); a.click(); setStatus("💾 Đã tải ảnh xuống!"); });
$("toggleMask").addEventListener("click", ()=>{ maskEnabled = !maskEnabled; $("maskBox").style.display = maskEnabled ? "block" : "none"; $("toggleMask").textContent = maskEnabled ? "❌ Tắt che chữ" : "🎨 Che chữ"; });
$("clearMask").addEventListener("click", ()=>{ if(!hasImage) return; maskCtx.clearRect(0,0,maskCanvas.width,maskCanvas.height); drawBase(); setStatus("🗑️ Đã xóa vùng che"); });
$("brush").addEventListener("input", (e)=>{ $("brushVal").textContent = e.target.value; });

function canvasPos(evt){ const rect = cv.getBoundingClientRect(); return { x: (evt.clientX - rect.left) * (cv.width / rect.width), y: (evt.clientY - rect.top) * (cv.height / rect.height) }; }
function paintAt(x,y){ const size = parseInt($("brush").value,10); maskCtx.save(); maskCtx.fillStyle = "rgba(255,255,255,0.95)"; maskCtx.beginPath(); maskCtx.arc(x,y,size/2,0,Math.PI*2); maskCtx.fill(); maskCtx.restore(); }

cv.addEventListener("mousedown", (e)=>{ if(!maskEnabled || !hasImage) return; isPainting = true; const p = canvasPos(e); paintAt(p.x,p.y); drawBase(); });
window.addEventListener("mouseup", ()=>{ isPainting = false; });
cv.addEventListener("mousemove", (e)=>{ if(!maskEnabled || !hasImage || !isPainting) return; paintAt(canvasPos(e).x, canvasPos(e).y); drawBase(); });

cv.addEventListener("touchstart", (e)=>{ if(!maskEnabled || !hasImage) return; e.preventDefault(); isPainting = true; const touch = e.touches[0]; const rect = cv.getBoundingClientRect(); paintAt( (touch.clientX - rect.left) * (cv.width / rect.width), (touch.clientY - rect.top) * (cv.height / rect.height) ); drawBase(); });
cv.addEventListener("touchmove", (e)=>{ if(!maskEnabled || !hasImage || !isPainting) return; e.preventDefault(); const touch = e.touches[0]; const rect = cv.getBoundingClientRect(); paintAt( (touch.clientX - rect.left) * (cv.width / rect.width), (touch.clientY - rect.top) * (cv.height / rect.height) ); drawBase(); });
cv.addEventListener("touchend", ()=>{ isPainting = false; });

$("openCamera").addEventListener("click", async ()=>{ try { stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } }); $("video").srcObject = stream; $("cameraModal").classList.add("active"); } catch(err) { alert("⚠️ Không thể mở camera: " + err.message); } });
$("closeCamera").addEventListener("click", ()=>{ if(stream){ stream.getTracks().forEach(t => t.stop()); stream = null; } $("cameraModal").classList.remove("active"); });
$("capture").addEventListener("click", ()=>{ const video = $("video"); const tempCanvas = document.createElement("canvas"); tempCanvas.width = video.videoWidth; tempCanvas.height = video.videoHeight; tempCanvas.getContext("2d").drawImage(video, 0, 0); loadImageFromUrl(tempCanvas.toDataURL("image/png")); if(stream){ stream.getTracks().forEach(t => t.stop()); stream = null; } $("cameraModal").classList.remove("active"); });
</script>
"""

@app.get("/")
@login_required
def index():
    user = current_user()
    return Response(render_page("TimeMark", INDEX_HTML, user), mimetype="text/html; charset=utf-8")


# Admin panel - FULL CODE HERE
@app.get("/admin")
@admin_required
def admin():
    user = current_user()
    db = get_db()
    users = db.execute("SELECT id, username, password, role, display_name, created_at FROM users ORDER BY role DESC, username ASC").fetchall()
    rows = []
    for u in users:
        display = u["display_name"] or u["username"]
        rows.append(
            "<tr>"
            f"<td><b>{display}</b><br/><small style='color:var(--muted);'>@{u['username']}</small></td>"
            f"<td><span class='badge'>🔑 {u['password']}</span></td>"
            f"<td><span class='badge'>{'👑 admin' if u['role']=='admin' else '👤 user'}</span></td>"
            f"<td><small style='color:var(--muted);'>{u['created_at']}</small></td>"
            "<td style='white-space:nowrap;'>"
            "<form method='post' action='/admin/set_display_name' style='display:inline; margin-right:8px;'>"
            f"<input type='hidden' name='username' value='{u['username']}'>"
            f"<input type='hidden' name='uid' value='{u['id']}'>"
            f"<input name='display_name' type='text' placeholder='Tên hiển thị' value='{display}' style='width:130px; display:inline-block; padding:8px;'> "
            "<button class='secondary' type='submit' style='padding:8px 12px;'>💾</button>"
            "</form>"
            "<form method='post' action='/admin/set_role' style='display:inline; margin-right:8px;'>"
            f"<input type='hidden' name='username' value='{u['username']}'>"
            f"<input type='hidden' name='uid' value='{u['id']}'>"
            "<select name='role' style='width:90px; display:inline-block; padding:8px;'>"
            f"<option value='user' {'selected' if u['role']=='user' else ''}>user</option>"
            f"<option value='admin' {'selected' if u['role']=='admin' else ''}>admin</option>"
            "</select> "
            "<button class='secondary' type='submit' style='padding:8px 12px;'>🔄</button>"
            "</form>"
            "<form method='post' action='/admin/set_password' style='display:inline; margin-right:8px;'>"
            f"<input type='hidden' name='username' value='{u['username']}'>"
            f"<input type='hidden' name='uid' value='{u['id']}'>"
            "<input name='new_password' type='text' placeholder='Mật khẩu mới' style='width:130px; display:inline-block; padding:8px;'> "
            "<button class='secondary' type='submit' style='padding:8px 12px;'>🔐</button>"
            "</form>"
            "<form method='post' action='/admin/delete_user' style='display:inline;' "
            "onsubmit='return confirm("⚠️ Xác nhận xóa user này?");'>"
            f"<input type='hidden' name='username' value='{u['username']}'>"
            f"<input type='hidden' name='uid' value='{u['id']}'>"
            "<button class='danger' type='submit' style='padding:8px 12px;'>🗑️</button>"
            "</form>"
            "</td></tr>"
        )
    table_rows = "\n".join(rows)
    body = (
        "<div class='center' style='max-width:1200px;'><div class='card'>"
        "<h2 style='margin:0 0 12px 0; font-size:24px; font-weight:800;'>⚙️ Quản lý người dùng</h2>"
        "<p style='color:var(--muted); margin-bottom:28px;'>Quản lý tài khoản, mật khẩu và quyền hạn</p>"
        "<h3 style='margin:24px 0 12px 0; font-size:16px; font-weight:700;'>➕ Tạo tài khoản mới</h3>"
        "<form method='post' action='/admin/create_user'>"
        "<div style='display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:12px;'>"
        "<div><label>Username</label><input name='username' type='text' required placeholder='vd: nguyenvana'></div>"
        "<div><label>Mật khẩu</label><input name='password' type='text' required placeholder='vd: 123456'></div>"
        "<div><label>Tên hiển thị</label><input name='display_name' type='text' placeholder='vd: Nguyễn Văn A'></div>"
        "<div><label>Quyền hạn</label><select name='role'><option value='user' selected>👤 User</option><option value='admin'>👑 Admin</option></select></div>"
        "</div>"
        "<div class='btns'>"
        "<button class='ok' type='submit'>✅ Tạo tài khoản</button>"
        "<a class='badge' href='/' style='padding:12px 20px;'>← Quay lại</a>"
        "</div>"
        "</form>"
        "<h3 style='margin:32px 0 12px 0; font-size:16px; font-weight:700;'>👥 Danh sách người dùng</h3>"
        "<div style='overflow-x:auto;'>"
        "<table>"
        "<thead><tr>"
        "<th>Người dùng</th>"
        "<th>Mật khẩu</th>"
        "<th>Quyền</th>"
        "<th>Tạo lúc</th>"
        "<th style='min-width:500px;'>Hành động</th>"
        "</tr></thead>"
        f"<tbody>{table_rows}</tbody>"
        "</table>"
        "</div>"
        "<div class='hint' style='margin-top:24px;'>"
        "💡 <b>Mẹo:</b> Bạn có thể xem mật khẩu của user ngay trong bảng. "
        "Dùng tài khoản <b>user</b> để share cho nhiều người cùng dùng."
        "</div>"
        "</div></div>"
    )
    return Response(render_page("Quản lý", body, user), mimetype="text/html; charset=utf-8")

@app.post("/admin/create_user")
@admin_required
def admin_create_user():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    display_name = (request.form.get("display_name") or "").strip()
    role = request.form.get("role") or "user"
    if not username or not password or role not in ("admin", "user"):
        return redirect("/admin")
    db = get_db()
    try:
        db.execute("INSERT INTO users(username,password,role,display_name) VALUES(?,?,?,?)",
            (username, password, role, display_name or username))
        db.commit()
    except sqlite3.IntegrityError:
        pass
    return redirect("/admin")

@app.post("/admin/set_display_name")
@admin_required
def admin_set_display_name():
    username = (request.form.get("username") or "").strip()
    display_name = (request.form.get("display_name") or "").strip()
    if not username:
        return redirect("/admin")
    db = get_db()
    db.execute("UPDATE users SET display_name=? WHERE username=?", (display_name, username))
    db.commit()
    return redirect("/admin")

@app.post("/admin/set_password")
@admin_required
def admin_set_password():
    username = (request.form.get("username") or "").strip()
    new_password = request.form.get("new_password") or ""
    uid = request.form.get("uid")
    if not username or not new_password:
        return redirect("/admin")
    db = get_db()
    db.execute("UPDATE users SET password=? WHERE username=?", (new_password, username))
    db.commit()
    if uid and session.get("uid") == int(uid):
        session.clear()
        return redirect("/login?msg=🔐+Mật+khẩu+đã+đổi,+vui+lòng+đăng+nhập+lại")
    return redirect("/admin")

@app.post("/admin/set_role")
@admin_required
def admin_set_role():
    username = (request.form.get("username") or "").strip()
    role = request.form.get("role") or "user"
    uid = request.form.get("uid")
    if not username or role not in ("admin", "user"):
        return redirect("/admin")
    db = get_db()
    if role == "user":
        admins = db.execute("SELECT COUNT(*) AS c FROM users WHERE role='admin'").fetchone()["c"]
        target = db.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
        if target and target["role"] == "admin" and admins <= 1:
            return redirect("/admin")
    db.execute("UPDATE users SET role=? WHERE username=?", (role, username))
    db.commit()
    if uid and session.get("uid") == int(uid):
        session["role"] = role
        if role != "admin":
            session.clear()
            return redirect("/login?msg=⚠️+Quyền+hạn+đã+thay+đổi,+vui+lòng+đăng+nhập+lại")
    return redirect("/admin")

@app.post("/admin/delete_user")
@admin_required
def admin_delete_user():
    username = (request.form.get("username") or "").strip()
    uid = request.form.get("uid")
    if not username:
        return redirect("/admin")
    db = get_db()
    target = db.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    if target and target["role"] == "admin":
        admins = db.execute("SELECT COUNT(*) AS c FROM users WHERE role='admin'").fetchone()["c"]
        if admins <= 1:
            return redirect("/admin")
    db.execute("DELETE FROM users WHERE username=?", (username,))
    db.commit()
    if uid and session.get("uid") == int(uid):
        session.clear()
        return redirect("/login?msg=⚠️+Tài+khoản+đã+bị+xóa")
    return redirect("/admin")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
