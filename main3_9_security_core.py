# main3_9_security_core.py
# ImageShare 3.9 — Security Core (基于 3.8)
# 新增: 图形验证码、登录日志、账户修改（用户名/密码）、图片删除/隐藏、管理员安全面板
# 依赖: flask pillow imagehash werkzeug
# pip install flask pillow imagehash werkzeug

import os
import json
import uuid
import hashlib
import datetime
import threading
import time
import random
import string
from functools import wraps
from flask import (
    Flask, render_template_string, request, redirect, url_for,
    flash, send_from_directory, session, abort, jsonify, make_response
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, ImageDraw, ImageFont, ImageFilter
import imagehash

# ---------------- CONFIG ----------------
APP_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_FILE = os.path.join(APP_DIR, "data.json")
UPLOADS_DIR = os.path.join(APP_DIR, "uploads")
AVATAR_DIR = os.path.join(APP_DIR, "avatars")
ALLOWED = {"png", "jpg", "jpeg", "gif", "bmp"}
PHASH_THRESHOLD = 6
SIMILAR_TRIGGER_COUNT = 3
TEMP_BAN_DAYS = 7

APP_VERSION = "3.9"
SECRET_KEY = os.environ.get("SECRET_KEY", "please-change-this-secret-to-a-strong-value")

# CAPTCHA config (图形验证码)
ENABLE_CAPTCHA = True
CAPTCHA_LENGTH = 5
CAPTCHA_WIDTH = 160
CAPTCHA_HEIGHT = 60
CAPTCHA_FONT_SIZE = 36
# 请把一个 ttf 字体放到项目目录或使用系统路径；否则使用 PIL 默认字体（效果较差）
FONT_PATH = os.path.join(APP_DIR, "fonts", "DejaVuSans-Bold.ttf")  # 可替换

# login lock config
MAX_LOGIN_ATTEMPTS = 5
LOCK_MINUTES = 5
CAPTCHA_THRESHOLD = 3  # 错误 3 次后开始要求验证码

os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(AVATAR_DIR, exist_ok=True)
os.makedirs(os.path.join(APP_DIR, "fonts"), exist_ok=True)

app = Flask(__name__)
app.secret_key = SECRET_KEY

# ---------------- DATA LAYER & MIGRATION ----------------
data_lock = threading.Lock()

def ensure_data_and_migrate():
    if not os.path.exists(DATA_FILE):
        d = {
            "version": APP_VERSION,
            "users": {},
            "images": {},
            "reports": [],
            "inspector_requests": [],
            "inspector_reports": [],
            "inspector_logs": [],
            "copyright_requests": [],
            "stats": {},
            "login_logs": [],
            "security": {"enable_captcha": ENABLE_CAPTCHA, "captcha_threshold": CAPTCHA_THRESHOLD},
        }
        # default admin
        d["users"]["admin"] = {
            "hashed": generate_password_hash("1234"),
            "is_admin": True,
            "created_at": datetime.datetime.utcnow().isoformat(),
            "disabled": False,
            "banned_until": None,
            "display_name": "admin",
            "similar_upload_count": 0,
            "upload_banned_until": None,
            "notifications": [],
            "is_inspector": False,
            "inspector_score": 0,
            "points": 100,
            "frozen": False,
            "favorites": [],
            "signature": "",
            "avatar": None,
            "failed_login": 0,
            "lock_until": None,
            "last_logins": []
        }
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=2)
        print("Created new data.json with default admin (admin / 1234)")
        return

    with open(DATA_FILE, "r", encoding="utf-8") as f:
        try:
            d = json.load(f)
        except Exception:
            bak = DATA_FILE + ".bak"
            os.rename(DATA_FILE, bak)
            print(f"Broken data.json moved to {bak}; creating fresh data.json")
            ensure_data_and_migrate()
            return

    changed = False
    # ensure fields
    for key in ("version","users","images","reports","inspector_requests","inspector_reports","inspector_logs","copyright_requests","stats","login_logs","security"):
        if key not in d:
            if key == "version":
                d[key] = APP_VERSION
            elif key in ("users","images"):
                d[key] = {}
            elif key == "security":
                d[key] = {"enable_captcha": ENABLE_CAPTCHA, "captcha_threshold": CAPTCHA_THRESHOLD}
            else:
                d[key] = []
            changed = True

    # normalize users/images like before...
    for uname, u in list(d.get("users", {}).items()):
        if not isinstance(u, dict):
            d["users"][uname] = {}
            u = d["users"][uname]
            changed = True
        if "hashed" not in u:
            if u.get("password"):
                u["hashed"] = generate_password_hash(u.get("password"))
                del u["password"]
            else:
                u["hashed"] = generate_password_hash("1234")
            changed = True
        u.setdefault("is_admin", False)
        u.setdefault("created_at", datetime.datetime.utcnow().isoformat())
        u.setdefault("disabled", False)
        u.setdefault("banned_until", None)
        u.setdefault("display_name", uname)
        u.setdefault("similar_upload_count", 0)
        u.setdefault("upload_banned_until", None)
        u.setdefault("notifications", [])
        u.setdefault("is_inspector", False)
        u.setdefault("inspector_score", 0)
        u.setdefault("points", 100)
        u.setdefault("frozen", False)
        u.setdefault("favorites", [])
        u.setdefault("signature", "")
        u.setdefault("avatar", None)
        u.setdefault("failed_login", 0)
        u.setdefault("lock_until", None)
        u.setdefault("last_logins", [])

    for iid, im in list(d.get("images", {}).items()):
        if not isinstance(im, dict):
            d["images"].pop(iid, None)
            changed = True
            continue
        im.setdefault("filename", None)
        im.setdefault("title", "")
        im.setdefault("uploader", None)
        im.setdefault("created_at", datetime.datetime.utcnow().isoformat())
        im.setdefault("upload_time", im.get("created_at") or "")
        im.setdefault("hash", None)
        im.setdefault("phash", None)
        im.setdefault("likes", [])
        im.setdefault("dislikes", [])
        im.setdefault("reports", [])
        im.setdefault("status", "visible")
        im.setdefault("hidden", False)  # 新增：隐藏标志
        im.setdefault("immune", False)
        im.setdefault("ban_time", None)
        im.setdefault("ban_reason", None)
        im.setdefault("copyright", {"status":"none","applicant":None,"realname":None,"id_card":None,"contact":None,"email":None,"reason":None,"review_reason":None,"approved_at":None,"similarity":0.0})
        im.setdefault("comments", [])
        im.setdefault("favorites_count", 0)

    if d.get("version") != APP_VERSION:
        d["version"] = APP_VERSION
        changed = True

    if changed:
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=2)
        print("Migrated/normalized data.json to version", APP_VERSION)

def load_data():
    ensure_data_and_migrate()
    with data_lock:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)

def save_data(d):
    with data_lock:
        if "version" not in d:
            d["version"] = APP_VERSION
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=2)

# ---------------- UTIL ----------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED

def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def compute_phash(path):
    try:
        img = Image.open(path)
        ph = str(imagehash.phash(img))
        return ph
    except Exception:
        return None

def phash_hamming(p1, p2):
    try:
        return imagehash.hex_to_hash(p1) - imagehash.hex_to_hash(p2)
    except Exception:
        return 999

def random_captcha_text(length=CAPTCHA_LENGTH):
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def generate_captcha_image(text):
    width = CAPTCHA_WIDTH
    height = CAPTCHA_HEIGHT
    try:
        if os.path.exists(FONT_PATH):
            font = ImageFont.truetype(FONT_PATH, CAPTCHA_FONT_SIZE)
        else:
            font = ImageFont.load_default()
    except Exception:
        font = ImageFont.load_default()
    image = Image.new('RGB', (width, height), (255, 255, 255))
    draw = ImageDraw.Draw(image)

    # background noise
    for _ in range(8):
        x1 = random.randint(0, width)
        y1 = random.randint(0, height)
        x2 = random.randint(0, width)
        y2 = random.randint(0, height)
        draw.line(((x1, y1), (x2, y2)), fill=(random.randint(140,200),random.randint(140,200),random.randint(140,200)), width=1)

    # draw text with slight offset per char
    char_width = width // len(text)
    for i, ch in enumerate(text):
        x = i * char_width + random.randint(2, max(2, char_width//4))
        y = random.randint(2, max(2, height - CAPTCHA_FONT_SIZE - 2))
        draw.text((x, y), ch, font=font, fill=(random.randint(0,80),random.randint(0,80),random.randint(0,80)))

    # dots
    for _ in range(200):
        draw.point((random.randint(0, width), random.randint(0, height)), fill=(random.randint(0,255),random.randint(0,255),random.randint(0,255)))

    image = image.filter(ImageFilter.GaussianBlur(0.8))
    return image

# ---------------- AUTH DECORATORS ----------------
def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            flash("请先登录", "err")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapped

def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        u = session.get("username")
        d = load_data()
        if not u or not d["users"].get(u, {}).get("is_admin"):
            abort(403)
        return f(*args, **kwargs)
    return wrapped

# ---------------- NOTIFICATIONS / INSPECTOR LOGS ----------------
def push_notification(username, typ, message, extra=None):
    d = load_data()
    u = d["users"].get(username)
    if not u:
        return
    note = {"type": typ, "message": message, "time": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), "read": False}
    if extra:
        note.update(extra)
    u.setdefault("notifications", []).append(note)
    save_data(d)

def log_inspection_action(inspector, image_title, action):
    d = load_data()
    rec = {"inspector": inspector, "image_title": image_title, "action": action, "time": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")}
    d.setdefault("inspector_logs", []).append(rec)
    save_data(d)

def update_inspector_score(inspector, correct=True):
    d = load_data()
    u = d["users"].get(inspector)
    if not u:
        return
    u.setdefault("inspector_score", 0)
    if correct:
        u["inspector_score"] += 10
    else:
        u["inspector_score"] -= 20
    log_inspection_action(inspector, "(score_update)", f"{'correct' if correct else 'incorrect'} -> score {u['inspector_score']}")
    if u.get("inspector_score", 0) < 0:
        u["is_inspector"] = False
        u["frozen"] = True
        u.setdefault("notifications", []).append({"type":"freeze_notice","message":"您的巡查权限因积分低于0被系统冻结，管理员将复核。","time":datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), "read": False})
    save_data(d)

def adjust_inspector_points(username, delta):
    d = load_data()
    u = d["users"].get(username)
    if not u:
        return
    u.setdefault("points", 100)
    u["points"] += delta
    log_inspection_action(username, "(points_update)", f"delta {delta} -> points {u['points']}")
    if u["points"] <= -20:
        u["frozen"] = True
        u.setdefault("notifications", []).append({"type":"system","message":"您的巡查资格因积分过低被系统冻结，请联系管理员。","time":datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), "read": False})
    save_data(d)

# ---------------- BACKGROUND SIMILARITY CHECK ----------------
def background_similarity_check(image_id, filepath):
    time.sleep(0.5)
    d = load_data()
    phash = compute_phash(filepath)
    filehash = sha256_of_file(filepath)
    dimg = d["images"].get(image_id)
    if not dimg:
        return
    dimg["hash"] = filehash
    dimg["phash"] = phash
    flagged_similar = False
    similar_list = []
    for oid, o in d["images"].items():
        if oid == image_id: continue
        if o.get("hash") and o.get("hash") == filehash:
            flagged_similar = True
            similar_list.append((oid, "exact"))
            continue
        if o.get("phash") and phash:
            ham = phash_hamming(phash, o.get("phash"))
            if ham <= PHASH_THRESHOLD:
                flagged_similar = True
                similar_list.append((oid, f"phash_ham={ham}"))
    if flagged_similar:
        dimg["hidden"] = True
        dimg["status"] = "under_review"
        save_data(d)
        urec = d["users"].get(dimg.get("uploader"))
        if urec:
            urec["similar_upload_count"] = urec.get("similar_upload_count", 0) + 1
            if urec["similar_upload_count"] >= SIMILAR_TRIGGER_COUNT:
                until = datetime.datetime.utcnow() + datetime.timedelta(days=TEMP_BAN_DAYS)
                urec["upload_banned_until"] = until.isoformat()
                urec["similar_upload_count"] = 0
                push_notification(dimg.get("uploader"), "system", f"检测到多次上传相似图片，上传权限被临时限制至 {urec['upload_banned_until']}")
        push_notification("admin", "system", f"上传图片 {dimg.get('title') or image_id} 被标记为相似并送审")
    else:
        dimg["hidden"] = False
        dimg["status"] = "visible"
        save_data(d)

# ---------------- BASE TEMPLATE (MOBILE-OPTIMIZED) ----------------
# (为了篇幅，此处保留你 3.8 的 BASE_TEMPLATE 原样 — 在真实文件中应把原模板全部复制过来)
BASE_TEMPLATE = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
  <title>ImageShare 3.9 Security Core</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { padding-top: 72px; background: var(--bg, #f5f7fb); color: var(--fg, #1b2430); transition: background .25s, color .25s; }
    .card-img-top { object-fit: cover; width: 100%; height: 180px; }
    .uploader { font-size: 0.9rem; color: var(--muted,#6c757d); }
    .avatar-sm { width:36px;height:36px;border-radius:50%;object-fit:cover; }
    .nav-notif { margin-right:10px; }
    .stat-card { min-height:100px; }
    .modal-img { max-width:100%; height:auto; }
    @media (max-width: 576px) { body { padding-top: 64px; } .card-img-top { height: 120px; } .card-body { padding: 0.5rem; } button.btn { font-size: 0.85rem; padding: 0.25rem 0.5rem; } .navbar-brand { font-size: 1rem; } }
  </style>
  <script>
    function setTheme(t) {
      if (t === 'dark') {
        document.documentElement.style.setProperty('--bg','#0f1720');
        document.documentElement.style.setProperty('--fg','#e6eef8');
        document.documentElement.style.setProperty('--muted','#9fb0c7');
        localStorage.setItem('theme','dark');
      } else {
        document.documentElement.style.setProperty('--bg','#f5f7fb');
        document.documentElement.style.setProperty('--fg','#1b2430');
        document.documentElement.style.setProperty('--muted','#6c757d');
        localStorage.setItem('theme','light');
      }
    }
    document.addEventListener('DOMContentLoaded', () => {
      const t = localStorage.getItem('theme') || 'light';
      setTheme(t);
      const el = document.getElementById('themeToggle');
      if (el) el.addEventListener('click', () => {
        const cur = localStorage.getItem('theme') || 'light';
        setTheme(cur === 'light' ? 'dark' : 'light');
      });
    });
    function openPreview(url, title){
      const img = document.getElementById('previewImage');
      const titleEl = document.getElementById('previewTitle');
      img.src = url;
      titleEl.textContent = title || '';
      const myModal = new bootstrap.Modal(document.getElementById('previewModal'));
      myModal.show();
    }
    async function postJSON(path, data) {
      const res = await fetch(path, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data)});
      return res.json();
    }
    function like(image_id){
      postJSON('/api/like', {image_id}).then(r => {
        if(r.success){
          const btn = document.getElementById('like-btn-'+image_id);
          if(btn) btn.textContent = '👍 ' + r.likes;
        } else alert(r.message || '操作失败');
      });
    }
    function favorite(image_id){
      postJSON('/api/favorite', {image_id}).then(r => {
        if(r.success){
          const btn = document.getElementById('fav-btn-'+image_id);
          if(btn) btn.textContent = r.favorited ? '★' : '☆';
        } else alert(r.message || '操作失败');
      });
    }
    async function postComment(image_id, parent_id=null){
      const input = document.getElementById('comment-input-'+image_id);
      if(!input) return;
      const text = input.value.trim();
      if(!text) { alert('评论不能为空'); return; }
      const res = await postJSON('/api/comment', {image_id, text, parent_id});
      if(res.success) location.reload();
      else alert(res.message || '评论失败');
    }
  </script>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light fixed-top shadow-sm" style="background: var(--bg,#f5f7fb);">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('index') }}" style="color: var(--fg,#1b2430);">ImageShare 3.9</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarMain">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarMain">
      <ul class="navbar-nav me-auto mb-2 mb-lg-0">
        <li class="nav-item"><a class="nav-link" href="{{ url_for('index') }}">画廊</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('upload') }}">上传</a></li>
        {% if is_admin %}
        <li class="nav-item"><a class="nav-link" href="{{ url_for('admin') }}">管理员</a></li>
        {% endif %}
        {% if user %}
        <li class="nav-item"><a class="nav-link" href="{{ url_for('inspector_mode') }}">巡查模式</a></li>
        {% endif %}
      </ul>
      <ul class="navbar-nav ms-auto align-items-center">
        <li class="nav-item me-2"><span id="themeToggle" class="badge bg-secondary" style="cursor:pointer;">主题</span></li>
        {% if user %}
          <li class="nav-item me-2 nav-notif"><a class="nav-link" href="{{ url_for('notifications') }}">🔔 <span class="badge bg-danger">{{ unread_count }}</span></a></li>
          <li class="nav-item me-2"><a class="nav-link" href="{{ url_for('profile', username=user) }}"><img src="{{ user_avatar or '' }}" class="avatar-sm" onerror="this.style.display='none'"/>  你好，<strong>{{ user }}</strong></a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}">登出</a></li>
        {% else %}
          <li class="nav-item"><a class="nav-link" href="{{ url_for('login') }}">登录</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('register') }}">注册</a></li>
        {% endif %}
      </ul>
    </div>
  </div>
</nav>

<div class="container mt-2">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      <div class="mt-2">
      {% for cat, m in messages %}
        <div class="alert alert-{{ 'danger' if cat=='err' else 'success' }} alert-dismissible fade show" role="alert">
          {{ m }} <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
      {% endfor %}
      </div>
    {% endif %}
  {% endwith %}
  {{ body|safe }}
</div>

<!-- 图片预览模态框 -->
<div class="modal fade" id="previewModal" tabindex="-1">
  <div class="modal-dialog modal-dialog-centered modal-xl">
    <div class="modal-content">
      <div class="modal-header">
        <h5 id="previewTitle" class="modal-title"></h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body text-center">
        <img id="previewImage" class="modal-img" src="" alt="preview"/>
      </div>
    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

# ---------------- RENDER HELPERS ----------------
def is_admin():
    u = session.get("username")
    if not u: return False
    d = load_data()
    return d["users"].get(u, {}).get("is_admin", False)

def render(body, **ctx):
    d = load_data()
    user = session.get("username")
    unread = 0
    user_avatar = None
    if user:
        u = d["users"].get(user, {})
        unread = sum(1 for n in u.get("notifications", []) if not n.get("read"))
        if u.get("avatar"):
            user_avatar = url_for('avatar_file', filename=u.get("avatar"))
    return render_template_string(BASE_TEMPLATE, body=body, user=user, is_admin=is_admin(), unread_count=unread, user_avatar=user_avatar, **ctx)

# ---------------- STATIC SERVE ----------------
@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOADS_DIR, filename)

@app.route("/avatars/<path:filename>")
def avatar_file(filename):
    return send_from_directory(AVATAR_DIR, filename)

# ---------------- CAPTCHA ROUTES ----------------
@app.route("/captcha.png")
def captcha_png():
    d = load_data()
    sec = d.get("security", {})
    if not sec.get("enable_captcha", ENABLE_CAPTCHA):
        # 返回 1x1 空白
        resp = make_response(b"\x89PNG\r\n\x1a\n")
        resp.headers['Content-Type'] = 'image/png'
        return resp
    # generate text and store in session
    text = random_captcha_text(CAPTCHA_LENGTH)
    session['captcha_text'] = text
    img = generate_captcha_image(text)
    from io import BytesIO
    buf = BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    resp = make_response(buf.read())
    resp.headers['Content-Type'] = 'image/png'
    # disable caching
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return resp

def verify_captcha(val):
    expected = session.get('captcha_text')
    session.pop('captcha_text', None)
    if not expected:
        return False
    return expected.lower() == (val or "").strip().lower()

# ---------------- LOGIN / REGISTER (增强登录记录/验证码) ----------------
@app.route("/login", methods=("GET","POST"))
def login():
    next_url = request.args.get("next") or url_for("index")
    d = load_data()
    sec = d.get("security", {})
    enable_captcha_setting = sec.get("enable_captcha", ENABLE_CAPTCHA)
    if request.method == "POST":
        username = request.form.get("username","").strip()
        pwd = request.form.get("password","")
        captcha_val = request.form.get("captcha","").strip()
        d = load_data()
        user = d["users"].get(username)
        if not user:
            flash("用户不存在", "err"); return redirect(url_for("login"))
        # check lock
        lock_until = user.get("lock_until")
        if lock_until:
            try:
                lu = datetime.datetime.fromisoformat(lock_until)
                if datetime.datetime.utcnow() < lu:
                    flash(f"账号被锁定至 {lock_until}，请稍后再试", "err")
                    return redirect(url_for("login"))
                else:
                    user["failed_login"] = 0
                    user["lock_until"] = None
            except:
                user["failed_login"] = 0
                user["lock_until"] = None
        if user.get("disabled"):
            flash("账号被禁用", "err"); return redirect(url_for("login"))
        if user.get("banned_until"):
            if user.get("banned_until") == "permanent":
                flash("账号已被封禁", "err"); return redirect(url_for("login"))
            try:
                t = datetime.datetime.fromisoformat(user.get("banned_until"))
                if datetime.datetime.utcnow() < t:
                    flash(f"账号被封禁至 {user.get('banned_until')}", "err"); return redirect(url_for("login"))
                else:
                    user["banned_until"] = None
            except:
                user["banned_until"] = None

        # CAPTCHA: if failed_login >= threshold or global enabled
        cap_needed = enable_captcha_setting and (user.get("failed_login",0) >= sec.get("captcha_threshold", CAPTCHA_THRESHOLD))
        if cap_needed:
            if not captcha_val:
                flash("请输入图形验证码", "err"); return redirect(url_for("login"))
            if not verify_captcha(captcha_val):
                user["failed_login"] = user.get("failed_login",0) + 1
                save_data(d)
                flash("验证码错误", "err"); return redirect(url_for("login"))

        if not check_password_hash(user.get("hashed",""), pwd):
            user["failed_login"] = user.get("failed_login",0) + 1
            if user["failed_login"] >= MAX_LOGIN_ATTEMPTS:
                until = datetime.datetime.utcnow() + datetime.timedelta(minutes=LOCK_MINUTES)
                user["lock_until"] = until.isoformat()
                flash(f"连续登录失败，账号已被锁定至 {user['lock_until']}", "err")
            else:
                flash("密码错误", "err")
            save_data(d)
            return redirect(url_for("login"))
        # success: reset counters, set session
        user["failed_login"] = 0
        user["lock_until"] = None
        # record login log (time, ip, ua) and per-user last_logins
        ip = request.remote_addr or ""
        ua = request.headers.get("User-Agent","")
        rec = {"user": username, "ip": ip, "ua": ua, "time": datetime.datetime.utcnow().isoformat()}
        d.setdefault("login_logs", []).append(rec)
        ulast = user.setdefault("last_logins", [])
        ulast.append(rec)
        # keep only last N
        user["last_logins"] = ulast[-10:]
        save_data(d)
        session["username"] = username
        flash("登录成功", "ok")
        return redirect(next_url)
    # GET
    body = '''
      <div class="row justify-content-center"><div class="col-md-5">
      <h4>登录</h4>
      <form method="post">
        <div class="mb-3"><input class="form-control" name="username" placeholder="用户名"></div>
        <div class="mb-3"><input class="form-control" name="password" placeholder="密码" type="password"></div>
    '''
    # show captcha image (always show if global enabled)
    sec = d.get("security", {})
    if sec.get("enable_captcha", ENABLE_CAPTCHA):
        body += '<div class="mb-2"><div class="input-group"><input class="form-control" name="captcha" placeholder="图形验证码" />'
        body += '<img src="%s" style="height:48px;margin-left:8px;cursor:pointer" onclick="this.src=\'/captcha.png?_=\'+Date.now()" title="点击刷新验证码"/></div></div>' % url_for('captcha_png')
    body += '''
        <button class="btn btn-primary">登录</button>
      </form>
      </div></div>
    '''
    return render(body)

# ---------------- REGISTER (同 3.8) ----------------
@app.route("/register", methods=("GET","POST"))
def register():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        pwd = request.form.get("password","")
        d = load_data()
        if not username or not pwd:
            flash("用户名/密码不能为空", "err"); return redirect(url_for("register"))
        if username in d["users"]:
            flash("用户名已存在", "err"); return redirect(url_for("register"))
        d["users"][username] = {
            "hashed": generate_password_hash(pwd),
            "is_admin": False,
            "created_at": datetime.datetime.utcnow().isoformat(),
            "disabled": False,
            "banned_until": None,
            "display_name": username,
            "similar_upload_count": 0,
            "upload_banned_until": None,
            "notifications": [],
            "is_inspector": False,
            "inspector_score": 0,
            "points": 100,
            "frozen": False,
            "favorites": [],
            "signature": "",
            "avatar": None,
            "failed_login": 0,
            "lock_until": None,
            "last_logins": []
        }
        save_data(d)
        flash("注册成功，请登录", "ok"); return redirect(url_for("login"))
    body = '''
      <div class="row justify-content-center"><div class="col-md-6">
      <h4>注册</h4>
      <form method="post">
        <div class="mb-3"><input class="form-control" name="username" placeholder="用户名"></div>
        <div class="mb-3"><input class="form-control" name="password" placeholder="密码" type="password"></div>
        <button class="btn btn-success">注册</button>
      </form>
      </div></div>
    '''
    return render(body)

# ---------------- SETTINGS: account (修改用户名/密码) ----------------
@app.route("/settings/account", methods=("GET","POST"))
@login_required
def settings_account():
    username = session["username"]
    d = load_data()
    u = d["users"].get(username)
    if not u:
        flash("用户不存在", "err"); return redirect(url_for("index"))
    if request.method == "POST":
        action = request.form.get("action")
        if action == "change_password":
            old = request.form.get("old_password","")
            new = request.form.get("new_password","")
            if not check_password_hash(u.get("hashed",""), old):
                flash("旧密码不正确", "err"); return redirect(url_for("settings_account"))
            if not new:
                flash("新密码不能为空", "err"); return redirect(url_for("settings_account"))
            u["hashed"] = generate_password_hash(new)
            save_data(d)
            flash("密码修改成功", "ok"); return redirect(url_for("settings_account"))
        if action == "change_username":
            newname = request.form.get("new_username","").strip()
            if not newname:
                flash("用户名不能为空", "err"); return redirect(url_for("settings_account"))
            if newname in d["users"]:
                flash("用户名已存在", "err"); return redirect(url_for("settings_account"))
            # perform rename: move user dict, update references
            d["users"][newname] = d["users"].pop(username)
            # update images uploader
            for iid, im in d["images"].items():
                if im.get("uploader") == username:
                    im["uploader"] = newname
                # comments etc.
                for c in im.get("comments", []):
                    if c.get("by") == username:
                        c["by"] = newname
                # favorites stored in user object; image favorites_count remains
            # update reports, inspector_requests, copyright requests, inspector_reports
            for r in d.get("reports", []):
                if r.get("by") == username:
                    r["by"] = newname
            for r in d.get("inspector_requests", []):
                if r.get("user") == username:
                    r["user"] = newname
            for r in d.get("inspector_reports", []):
                if r.get("inspector") == username:
                    r["inspector"] = newname
            for r in d.get("copyright_requests", []):
                if r.get("applicant") == username:
                    r["applicant"] = newname
            # update session
            session["username"] = newname
            save_data(d)
            flash("用户名修改成功", "ok"); return redirect(url_for("settings_account"))
    # GET: show form + recent logins
    last = u.get("last_logins", [])[-5:]
    last_html = "<ul>"
    for l in reversed(last):
        last_html += f"<li>{l.get('time')} / {l.get('ip')} / {l.get('ua')[:60]}</li>"
    last_html += "</ul>"
    body = f'''
      <div class="row"><div class="col-md-8">
        <h4>账户设置 - {username}</h4>
        <h5>修改密码</h5>
        <form method="post">
          <input type="hidden" name="action" value="change_password" />
          <div class="mb-2"><input class="form-control" name="old_password" placeholder="旧密码" type="password"/></div>
          <div class="mb-2"><input class="form-control" name="new_password" placeholder="新密码" type="password"/></div>
          <button class="btn btn-primary btn-sm">修改密码</button>
        </form>
        <hr>
        <h5>修改用户名</h5>
        <form method="post">
          <input type="hidden" name="action" value="change_username" />
          <div class="mb-2"><input class="form-control" name="new_username" placeholder="新用户名"/></div>
          <button class="btn btn-warning btn-sm">修改用户名</button>
        </form>
        <hr>
        <h5>最近登录</h5>
        {last_html}
      </div></div>
    '''
    return render(body)

# ---------------- IMAGE MANAGEMENT: delete / hide ----------------
@app.route("/image/manage/<image_id>", methods=("POST",))
@login_required
def image_manage(image_id):
    action = request.form.get("action")
    d = load_data()
    im = d["images"].get(image_id)
    if not im:
        flash("图片不存在", "err"); return redirect(url_for("index"))
    username = session["username"]
    u = d["users"].get(username)
    # only owner or admin
    if im.get("uploader") != username and not u.get("is_admin"):
        flash("无权限操作该图片", "err"); return redirect(url_for("detail", image_id=image_id))
    if action == "delete":
        # require confirmation token or confirm param
        confirm = request.form.get("confirm")
        if confirm != "yes":
            flash("请确认删除操作", "err"); return redirect(url_for("detail", image_id=image_id))
        # delete file
        fn = im.get("filename")
        if fn:
            try:
                path = os.path.join(UPLOADS_DIR, fn)
                if os.path.exists(path):
                    os.remove(path)
            except:
                pass
        # remove references: favorites, reports, inspector_reports, copyright_requests
        for uname, user in d["users"].items():
            favs = user.get("favorites", [])
            if image_id in favs:
                favs.remove(image_id)
        # remove from images dict
        d["images"].pop(image_id, None)
        # remove reports entries for this image
        d["reports"] = [r for r in d.get("reports", []) if r.get("image_id") != image_id]
        d["inspector_reports"] = [r for r in d.get("inspector_reports", []) if r.get("image_id") != image_id]
        d["copyright_requests"] = [r for r in d.get("copyright_requests", []) if r.get("image_id") != image_id]
        save_data(d)
        flash("图片已删除", "ok"); return redirect(url_for("index"))
    if action == "toggle_hide":
        im["hidden"] = not im.get("hidden", False)
        save_data(d)
        flash("已更新图片可见性", "ok"); return redirect(url_for("detail", image_id=image_id))
    flash("未知操作", "err"); return redirect(url_for("detail", image_id=image_id))

# ---------------- ADMIN: login logs & security settings ----------------
@app.route("/admin/login_logs")
@admin_required
def admin_login_logs():
    d = load_data()
    logs = list(reversed(d.get("login_logs", [])[-200:]))
    body = "<h4>登录日志（最近 200 条）</h4>"
    if not logs:
        body += "<p class='text-muted'>暂无记录</p>"
    else:
        body += "<table class='table table-sm'><thead><tr><th>时间</th><th>用户名</th><th>IP</th><th>UA</th></tr></thead><tbody>"
        for l in logs:
            body += f"<tr><td>{l.get('time')}</td><td>{l.get('user')}</td><td>{l.get('ip')}</td><td>{l.get('ua')[:120]}</td></tr>"
        body += "</tbody></table>"
    return render(body)

@app.route("/admin/security", methods=("GET","POST"))
@admin_required
def admin_security():
    d = load_data()
    sec = d.get("security", {})
    if request.method == "POST":
        enable = True if request.form.get("enable_captcha") == "on" else False
        threshold = int(request.form.get("captcha_threshold") or CAPTCHA_THRESHOLD)
        sec["enable_captcha"] = enable
        sec["captcha_threshold"] = threshold
        d["security"] = sec
        save_data(d)
        flash("安全设置已保存", "ok"); return redirect(url_for("admin_security"))
    body = f'''
      <h4>安全设置</h4>
      <form method="post">
        <div class="form-check mb-2">
          <input class="form-check-input" type="checkbox" name="enable_captcha" id="enable_captcha" {"checked" if sec.get("enable_captcha", True) else ""}/>
          <label class="form-check-label" for="enable_captcha">启用图形验证码</label>
        </div>
        <div class="mb-2"><label>验证码触发阈值（失败次数）</label><input class="form-control" name="captcha_threshold" value="{sec.get('captcha_threshold', CAPTCHA_THRESHOLD)}" /></div>
        <button class="btn btn-primary btn-sm">保存设置</button>
      </form>
    '''
    return render(body)

# ---------------- INSPECTOR APPLY BUTTON restored (页面中会显示申请入口) ----------------
@app.route("/inspector/apply", methods=("GET","POST"))
@login_required
def inspector_apply():
    username = session["username"]
    d = load_data()
    # check existing application
    existing = None
    for r in d.get("inspector_requests", []):
        if r.get("user") == username:
            existing = r
            break
    ok, reason = can_apply_inspector(username)
    if request.method == "POST":
        if existing and existing.get("status") == "pending":
            flash("您已提交了巡查员申请，正在等待审核", "err"); return redirect(url_for("inspector_apply"))
        if not ok:
            flash(f"您不符合申请条件：{reason}", "err"); return redirect(url_for("inspector_apply"))
        realname = request.form.get("realname","").strip()
        ic = request.form.get("ic","").strip()
        contact = request.form.get("contact","").strip()
        reason_txt = request.form.get("reason","").strip()
        if not all([realname, ic, contact, reason_txt]):
            flash("请完整填写所有项", "err"); return redirect(url_for("inspector_apply"))
        req = {"user": username, "real_name": realname, "ic": ic, "contact": contact, "reason": reason_txt, "time": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), "status":"pending"}
        d.setdefault("inspector_requests", []).append(req)
        save_data(d)
        flash("巡查员申请已提交，等待管理员审核", "ok"); return redirect(url_for("index"))
    # GET: show current status if exists
    body = f'''
      <div class="row justify-content-center"><div class="col-md-8">
        <h4>申请成为巡查员</h4>
        <p>申请用户：{username}</p>
        <p>申请条件说明：账号需注册至少 7 天、上传至少 5 张、历史举报失误率低</p>
    '''
    if existing:
        body += f"<div class='alert alert-info'>您已有申请：状态 — <strong>{existing.get('status')}</strong>；申请时间：{existing.get('time')}</div>"
        if existing.get("status") == "rejected":
            body += "<div class='alert alert-warning'>您上次的申请被拒绝。如需再次申请，请确认资料改进后再提交。</div>"
    if not ok:
        body += f"<div class='alert alert-warning'>您暂不符合申请条件：{reason}</div>"
    # form
    body += '''
        <form method="post">
          <div class="mb-3"><input class="form-control" name="realname" placeholder="真实姓名"></div>
          <div class="mb-3"><input class="form-control" name="ic" placeholder="身份证号"></div>
          <div class="mb-3"><input class="form-control" name="contact" placeholder="联系方式（电话/邮箱）"></div>
          <div class="mb-3"><textarea class="form-control" name="reason" placeholder="申请理由（说明为何适合巡查）"></textarea></div>
          <button class="btn btn-primary">提交申请</button>
        </form>
      </div></div>
    '''
    return render(body)

def can_apply_inspector(username):
    d = load_data()
    u = d["users"].get(username)
    if not u:
        return False, "用户不存在"
    try:
        created = datetime.datetime.fromisoformat(u.get("created_at"))
        if (datetime.datetime.utcnow() - created).days < 7:
            return False, "账号注册时间不足 7 天"
    except:
        pass
    uploads = [im for im in d["images"].values() if im.get("uploader")==username]
    if len(uploads) < 5:
        return False, "上传图片少于 5 张"
    # 可添加更多检测：误报率、历史违规等
    return True, ""

# ---------------- IMAGE DETAIL (增加删除/隐藏按钮) ----------------
@app.route("/detail/<image_id>")
def detail(image_id):
    d = load_data()
    im = d["images"].get(image_id)
    if not im:
        flash("图片不存在", "err"); return redirect(url_for("index"))
    imgurl = url_for("uploaded_file", filename=im.get("filename")) if im.get("filename") else ""
    title = im.get("title") or "(无标题)"
    uploader = im.get("uploader") or "系统"
    status = im.get("status")
    similar = None
    if im.get("phash"):
        for oid, o in d["images"].items():
            if oid == image_id: continue
            if o.get("phash"):
                ham = phash_hamming(im.get("phash"), o.get("phash"))
                if ham <= PHASH_THRESHOLD:
                    similar = {"id": oid, "title": o.get("title"), "ham": ham, "url": url_for("uploaded_file", filename=o.get("filename"))}
                    break
    comments_html = ""
    for c in im.get("comments", []):
        by = c.get("by")
        time = c.get("time")
        text = c.get("text")
        reply_to = c.get("reply_to")
        avatar = None
        urec = d["users"].get(by, {})
        if urec and urec.get("avatar"):
            avatar = url_for('avatar_file', filename=urec.get("avatar"))
        reply_html = ""
        if reply_to is not None:
            p = None
            for pc in im.get("comments", []):
                if pc.get("index") == reply_to:
                    p = pc; break
            if p:
                reply_html = f'<div class="ps-2"><small>回复 @{p.get("by")}: {p.get("text")}</small></div>'
        comments_html += f'''
          <div class="mb-2">
            <div><img src="{avatar or ''}" class="avatar-sm" /> <strong>{by}</strong> <small class="text-muted">[{time}]</small></div>
            {reply_html}
            <div>{text}</div>
          </div>
        '''
    # show copyright apply button if no pending/approved claim
    copyright_msg = ""
    cr_pending = any((r for r in d.get("copyright_requests", []) if r.get("image_id")==image_id and r.get("status")=="pending"))
    cr_approved = any((r for r in d.get("copyright_requests", []) if r.get("image_id")==image_id and r.get("status")=="approved"))
    if cr_pending:
        copyright_msg = '<div class="alert alert-info">该图片已有版权申请正在审核中。</div>'
    elif cr_approved:
        copyright_msg = '<div class="alert alert-success">该图片已有版权认领（已通过）。</div>'
    else:
        copyright_msg = f'<a class="btn btn-sm btn-outline-primary" href="{url_for("apply_copyright", image_id=image_id)}">申请版权</a>'

    # account-level controls: delete / hide (owner or admin)
    control_html = ""
    user = session.get("username")
    if user:
        urec = d["users"].get(user, {})
        if urec and (urec.get("is_admin") or im.get("uploader")==user):
            # show hide toggle and delete (delete needs JS confirm)
            hide_label = "显示" if im.get("hidden") else "隐藏"
            control_html = f'''
              <form method="post" action="{url_for('image_manage', image_id=image_id)}" onsubmit="return confirmDelete(this);">
                <input type="hidden" name="action" value="toggle_hide" />
                <button class="btn btn-sm btn-outline-secondary" type="submit">{hide_label}</button>
              </form>
              <form method="post" action="{url_for('image_manage', image_id=image_id)}" style="display:inline;" onsubmit="return confirmDelete(this);">
                <input type="hidden" name="action" value="delete" />
                <input type="hidden" name="confirm" value="yes" />
                <button class="btn btn-sm btn-danger" type="submit">删除</button>
              </form>
              <script>
                function confirmDelete(form){
                  if(form.querySelector('input[name=action]').value === 'delete'){
                    return confirm('确定要删除该图片？删除后无法恢复。');
                  }
                  return true;
                }
              </script>
            '''

    body = f'''
      <div class="row">
        <div class="col-md-6">
          <div class="card"><div class="card-body text-center">
            <img src="{imgurl}" class="img-fluid" style="max-height:520px; cursor:pointer;" onclick="openPreview('{imgurl}','{title}')" />
          </div></div>
        </div>
        <div class="col-md-6">
          <h4>{title}</h4>
          <p class="text-muted">上传者：{uploader}</p>
          <p>状态：<strong>{status}{' · 已隐藏' if im.get('hidden') else ''}</strong></p>
          <div class="mb-3">
            <form action="{url_for('report', image_id=image_id)}" method="post">
              <div class="mb-2"><textarea class="form-control" name="reason" placeholder="举报理由（可空）"></textarea></div>
              <button class="btn btn-danger btn-sm">举报</button>
              <a class="btn btn-outline-secondary btn-sm" href="{url_for('index')}">返回</a>
            </form>
          </div>
          <div class="mb-2">{control_html}</div>
          <hr>
          <h6>互动</h6>
          <div class="mb-2">
            <button class="btn btn-sm btn-outline-primary" id="like-btn-{image_id}" onclick="like('{image_id}')">👍 {len(im.get('likes',[]))}</button>
            <button class="btn btn-sm btn-outline-warning" id="fav-btn-{image_id}" onclick="favorite('{image_id}')">☆</button>
          </div>
          <hr>
          <h6>评论</h6>
          {comments_html}
          <div class="mb-2"><input id="comment-input-{image_id}" class="form-control" placeholder="发表评论"></div>
          <div><button class="btn btn-sm btn-primary" onclick="postComment('{image_id}')">发表评论</button></div>
          <div class="mt-3">{copyright_msg}</div>
    '''
    if similar:
        body += f'''
          <div class="mt-4">
            <h6>检测到可能相似图片（汉明距离 {similar['ham']}）</h6>
            <a href="{url_for('detail', image_id=similar['id'])}"><img src="{similar['url']}" style="height:120px"></a>
          </div>
        '''
    body += "</div></div>"
    return render(body)

# ---------------- REST OF ROUTES (index, upload, inspector flow, admin etc.) ----------------
# 为了避免重复，这里保留与你 3.8 同步的其它路由（index, upload, report, inspector_mode, admin...）
# 在真实文件中请把 3.8 中剩余路由全部保留。上面我已覆盖并扩展关键点（登录、注册、settings、captcha、image management、admin security/login_logs）。

@app.route("/")
def index():
    d = load_data()
    images = list(d["images"].items())
    images.sort(key=lambda x: x[1].get("created_at",""), reverse=True)
    body = '<div class="row mb-3"><div class="col-8"><h4>画廊</h4></div><div class="col-4 text-end"><small class="text-muted">本地 · 版本 %s</small></div></div><div class="row">' % d.get("version", APP_VERSION)
    for iid, im in images:
        if im.get("status") == "banned":
            continue
        if im.get("hidden") and not (session.get("username") and (session.get("username")==im.get("uploader") or is_admin())):
            # 隐藏图片对非上传者/非管理员不可见
            continue
        thumb_url = url_for("uploaded_file", filename=im.get("filename")) if im.get("filename") else ""
        title = im.get("title") or "(无标题)"
        uploader = im.get("uploader") or "系统"
        like_btn = f'<button class="btn btn-sm btn-outline-primary" id="like-btn-{iid}" onclick="like(\'{iid}\')">👍 {len(im.get("likes",[]))}</button>'
        fav_btn = f'<button class="btn btn-sm btn-outline-warning" id="fav-btn-{iid}" onclick="favorite(\'{iid}\')">☆</button>'
        body += f'''
          <div class="col-12 col-sm-6 col-md-4 col-lg-3 mb-4">
            <div class="card h-100 shadow-sm">
              <div style="cursor:pointer;" onclick="openPreview('{thumb_url}','{title}')">
                <img src="{thumb_url}" class="card-img-top" alt="{title}" />
              </div>
              <div class="card-body d-flex flex-column">
                <h6 class="card-title">{title}</h6>
                <p class="uploader mb-2">上传：{uploader}</p>
                <div class="mt-auto d-flex justify-content-between align-items-center">
                  <a class="btn btn-sm btn-primary" href="{url_for('detail', image_id=iid)}">查看</a>
                  <div>{like_btn} {fav_btn}</div>
                </div>
              </div>
            </div>
          </div>
        '''
    body += "</div>"
    return render(body)

# ---------------- API endpoints for like/favorite/comment (copy from 3.8) ----------------
@app.route("/api/comment", methods=("POST",))
@login_required
def api_comment():
    data = request.get_json() or {}
    image_id = data.get("image_id")
    text = data.get("text","").strip()
    parent = data.get("parent_id")
    if not text:
        return jsonify({"success": False, "message": "评论不能为空"})
    d = load_data()
    im = d["images"].get(image_id)
    if not im:
        return jsonify({"success": False, "message": "图片不存在"})
    comment = {"by": session["username"], "text": text, "time": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), "reply_to": parent, "index": int(uuid.uuid4().int & (1<<31)-1)}
    im.setdefault("comments", []).append(comment)
    save_data(d)
    return jsonify({"success": True})

@app.route("/api/like", methods=("POST",))
@login_required
def api_like():
    data = request.get_json() or {}
    image_id = data.get("image_id")
    d = load_data()
    im = d["images"].get(image_id)
    if not im:
        return jsonify({"success": False, "message": "图片不存在"})
    user = session["username"]
    likes = im.setdefault("likes", [])
    if user in likes:
        likes.remove(user)
    else:
        likes.append(user)
    save_data(d)
    return jsonify({"success": True, "likes": len(likes)})

@app.route("/api/favorite", methods=("POST",))
@login_required
def api_favorite():
    data = request.get_json() or {}
    image_id = data.get("image_id")
    d = load_data()
    im = d["images"].get(image_id)
    if not im:
        return jsonify({"success": False, "message": "图片不存在"})
    user = session["username"]
    urec = d["users"].get(user)
    favs = urec.setdefault("favorites", [])
    if image_id in favs:
        favs.remove(image_id)
        favorited = False
    else:
        favs.append(image_id)
        favorited = True
    save_data(d)
    return jsonify({"success": True, "favorited": favorited})

# ---------------- remaining routes (upload, report, inspector flow, admin handlers) should be copied from your 3.8 file.
# For brevity they are expected to remain unchanged except for respecting new 'hidden' flag and new account rename behavior.

if __name__ == "__main__":
    ensure_data_and_migrate()
    app.run(host="0.0.0.0", port=5000, debug=True)
