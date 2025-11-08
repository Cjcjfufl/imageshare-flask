# main3_8_admin_optimize.py
# ImageShare 3.8 — 基于 3.4 的增强管理员面板（解封/解禁/解冻/版权申请/巡查员申请状态）
# 依赖: flask pillow imagehash
# pip install -r requirements.txt

import os
import json
import uuid
import hashlib
import datetime
import threading
import time
from functools import wraps
from flask import (
    Flask, render_template_string, request, redirect, url_for,
    flash, send_from_directory, session, abort, jsonify
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image
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

APP_VERSION = "3.8"
SECRET_KEY = os.environ.get("SECRET_KEY", "please-change-this-secret-to-a-strong-value")

# login lock config
MAX_LOGIN_ATTEMPTS = 5
LOCK_MINUTES = 5

os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(AVATAR_DIR, exist_ok=True)

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
            "stats": {}
        }
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
            "lock_until": None
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
    for key in ("version","users","images","reports","inspector_requests","inspector_reports","inspector_logs","copyright_requests","stats"):
        if key not in d:
            if key == "version":
                d[key] = APP_VERSION
            elif key in ("users","images"):
                d[key] = {}
            else:
                d[key] = []
            changed = True

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
        im.setdefault("hidden", False)
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
BASE_TEMPLATE = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
  <title>ImageShare 3.8</title>
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
    <a class="navbar-brand" href="{{ url_for('index') }}" style="color: var(--fg,#1b2430);">ImageShare 3.8</a>
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
          <li class="nav-item me-2"><a class="nav-link" href="{{ url_for('profile', username=user) }}"><img src="{{ user_avatar or '' }}" class="avatar-sm" onerror="this.style.display='none'"/> 你好，<strong>{{ user }}</strong></a></li>
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

# ---------------- PAGES & AUTH (same as previous, omitted here for brevity) ----------------
# For brevity in this paste, assume the standard routes (index, login, logout, register, upload, detail, report,
# inspector_apply, inspector_mode, submit_inspector_report, admin_inspector_requests, admin_inspector_reports, etc.)
# are preserved from the previous 3.4 code with the following targeted enhancements implemented below.
#
# --- ENHANCEMENTS IMPLEMENTED BELOW ---
#

# ---------------- ENHANCED: Inspector apply (prevent duplicates, show status) ----------------
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

# ---------------- ENHANCED: Copyright application (user) ----------------
@app.route("/copyright/apply/<image_id>", methods=("GET","POST"))
@login_required
def apply_copyright(image_id):
    d = load_data()
    im = d["images"].get(image_id)
    if not im:
        flash("图片不存在", "err"); return redirect(url_for("index"))
    if request.method == "POST":
        realname = request.form.get("realname","").strip()
        email = request.form.get("email","").strip()
        reason = request.form.get("reason","").strip()
        if not all([realname, email, reason]):
            flash("请完整填写所有项", "err"); return redirect(url_for("apply_copyright", image_id=image_id))
        req = {
            "image_id": image_id,
            "image_title": im.get("title"),
            "applicant": session["username"],
            "realname": realname,
            "email": email,
            "reason": reason,
            "status": "pending",
            "time": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "reviewer": None,
            "review_reason": None,
            "approved_at": None
        }
        d.setdefault("copyright_requests", []).append(req)
        save_data(d)
        flash("版权申请已提交，管理员将审核", "ok"); return redirect(url_for("detail", image_id=image_id))
    body = f'''
      <div class="row justify-content-center"><div class="col-md-8">
        <h4>为图片《{im.get("title")}》申请版权</h4>
        <form method="post">
          <div class="mb-2"><input class="form-control" name="realname" placeholder="真实姓名"></div>
          <div class="mb-2"><input class="form-control" name="email" placeholder="联系邮箱"></div>
          <div class="mb-2"><textarea class="form-control" name="reason" placeholder="说明为何您拥有版权（证据/说明）"></textarea></div>
          <button class="btn btn-primary">提交申请</button>
        </form>
      </div></div>
    '''
    return render(body)

# ---------------- ENHANCED: Admin - copyright review ----------------
@app.route("/admin/copyrights")
@admin_required
def admin_copyrights():
    d = load_data()
    reqs = d.get("copyright_requests", [])
    body = '<h4>版权申请列表</h4>'
    if not reqs:
        body += '<p class="text-muted">暂无版权申请</p>'
    else:
        for i, r in enumerate(reqs):
            body += f'''
              <div class="card mb-2 p-2">
                <div><strong>{r.get("image_title")}</strong> (ID: {r.get("image_id")})</div>
                <div>申请人：{r.get("applicant")}  时间：{r.get("time")}  状态：<strong>{r.get("status")}</strong></div>
                <div>姓名：{r.get("realname")}  联系：{r.get("email")}</div>
                <div class="mt-2">理由：{r.get("reason")}</div>
                <div class="mt-2">
                  <a class="btn btn-sm btn-success" href="{url_for('admin_handle_copyright', action='approve', idx=i)}">批准</a>
                  <a class="btn btn-sm btn-danger" href="{url_for('admin_handle_copyright', action='reject', idx=i)}">拒绝</a>
                </div>
              </div>
            '''
    return render(body)

@app.route("/admin/copyright/<action>/<int:idx>")
@admin_required
def admin_handle_copyright(action, idx):
    d = load_data()
    reqs = d.get("copyright_requests", [])
    if idx < 0 or idx >= len(reqs):
        flash("申请不存在", "err"); return redirect(url_for("admin_copyrights"))
    req = reqs[idx]
    if req.get("status") != "pending":
        flash("该申请已处理", "err"); return redirect(url_for("admin_copyrights"))
    req["status"] = "approved" if action == "approve" else "rejected"
    req["reviewer"] = session.get("username")
    req["review_reason"] = f"{action} by admin {session.get('username')}"
    req["approved_at"] = datetime.datetime.utcnow().isoformat() if action == "approve" else None
    # if approved, mark the image copyright status
    img = d["images"].get(req.get("image_id"))
    if action == "approve" and img:
        img["copyright"] = img.get("copyright", {})
        img["copyright"].update({"status": "claimed", "applicant": req.get("applicant"), "realname": req.get("realname"), "email": req.get("email"), "approved_at": req.get("approved_at")})
        push_notification(img.get("uploader"), "system", f"您的图片《{img.get('title')}》的版权申请被管理员批准。")
    save_data(d)
    flash("已处理版权申请", "ok"); return redirect(url_for("admin_copyrights"))

# ---------------- ENHANCED: Admin - user actions (unban/un-disable/unfreeze) ----------------
@app.route("/admin/user/<action>/<user>")
@admin_required
def admin_user_action(action, user):
    d = load_data()
    u = d["users"].get(user)
    if not u:
        flash("用户不存在", "err"); return redirect(url_for("admin", tab="users"))
    if action == "ban":
        u["banned_until"] = "permanent"
        save_data(d); flash("用户已永久封禁", "ok"); return redirect(url_for("admin", tab="users"))
    if action == "unban":
        u["banned_until"] = None
        save_data(d); flash("用户封禁已解除", "ok"); return redirect(url_for("admin", tab="users"))
    if action == "disable":
        u["disabled"] = True; save_data(d); flash("用户已禁用", "ok"); return redirect(url_for("admin", tab="users"))
    if action == "enable":
        u["disabled"] = False; save_data(d); flash("用户已解除禁用", "ok"); return redirect(url_for("admin", tab="users"))
    if action == "freeze_inspector":
        u["is_inspector"] = False; u["frozen"] = True
        u.setdefault("notifications", []).append({"type":"freeze_notice","message":"您的巡查权限已被管理员冻结。","time":datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), "read": False})
        save_data(d); flash("已冻结该巡查员", "ok"); return redirect(url_for("admin", tab="users"))
    if action == "restore_inspector":
        u["is_inspector"] = True; u["frozen"] = False
        u.setdefault("notifications", []).append({"type":"unfreeze_notice","message":"您的巡查权限已被管理员恢复。","time":datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), "read": False})
        save_data(d); flash("已恢复巡查员资格", "ok"); return redirect(url_for("admin", tab="users"))
    flash("未知操作", "err"); return redirect(url_for("admin"))

# ---------------- ENHANCED: Admin main panel — show extra buttons + copyright tab ----------------
@app.route("/admin")
@admin_required
def admin():
    tab = request.args.get("tab","overview")
    d = load_data()
    total_images = len(d["images"])
    total_users = len(d["users"])
    total_reports = len(d.get("reports", []))
    inspectors = sorted([ (u,ud.get("inspector_score",0)) for u,ud in d["users"].items() if ud.get("is_inspector") ], key=lambda x: x[1], reverse=True)[:10]
    body = '<div class="row">'
    body += '<div class="col-md-8">'
    if tab == "overview":
        body += f'<h4>管理员仪表盘</h4><div class="row"><div class="col-md-4"><div class="card stat-card p-3"><h5>{total_images}</h5><div>图片数</div></div></div><div class="col-md-4"><div class="card stat-card p-3"><h5>{total_users}</h5><div>用户数</div></div></div><div class="col-md-4"><div class="card stat-card p-3"><h5>{total_reports}</h5><div>举报数</div></div></div></div><h5 class="mt-3">巡查员排行榜</h5>'
        body += '<ol>'
        for name, score in inspectors:
            body += f'<li>{name} — {score}</li>'
        body += '</ol>'
    elif tab == "images":
        pending = [(iid, im) for iid, im in d["images"].items() if im.get("status") in ("under_review","processing")]
        body += '<h4>图片审查</h4>'
        if not pending:
            body += '<p class="text-muted">暂无待审图片</p>'
        else:
            for iid, im in pending:
                thumb = url_for("uploaded_file", filename=im.get("filename"))
                body += f'''
                  <div class="card mb-2"><div class="row g-0">
                    <div class="col-3"><img src="{thumb}" class="img-fluid"></div>
                    <div class="col-9"><div class="card-body">
                      <h6>{im.get("title")}</h6>
                      <p class="text-muted">上传：{im.get("uploader")}  状态：{im.get("status")}</p>
                      <a class="btn btn-sm btn-success" href="{url_for('admin_action', action='approve', image_id=iid)}">通过</a>
                      <a class="btn btn-sm btn-danger" href="{url_for('admin_action', action='ban_image', image_id=iid)}">封禁</a>
                    </div></div>
                  </div></div>
                '''
    elif tab == "users":
        body += '<h4>用户管理</h4>'
        for uname,u in d["users"].items():
            flags = []
            if u.get("is_admin"): flags.append("管理员")
            if u.get("is_inspector"): flags.append("巡查")
            if u.get("disabled"): flags.append("已禁用")
            if u.get("banned_until"): flags.append(f"已封禁({u.get('banned_until')})")
            if u.get("frozen"): flags.append("巡查被冻结")
            flag_text = " · ".join(flags)
            body += f'<div class="d-flex justify-content-between align-items-center mb-2"><div><strong>{uname}</strong><br><small class="text-muted">{u.get("display_name")}{ " · "+flag_text if flag_text else ""}</small><br><small class="text-muted">score={u.get("inspector_score",0)} points={u.get("points",100)}</small></div><div>'
            if not u.get("is_admin"):
                if not u.get("banned_until"):
                    body += f'<a class="btn btn-sm btn-warning" href="{url_for("admin_user_action", action="ban", user=uname)}">封禁</a> '
                else:
                    body += f'<a class="btn btn-sm btn-success" href="{url_for("admin_user_action", action="unban", user=uname)}">解除封禁</a> '
                if not u.get("disabled"):
                    body += f'<a class="btn btn-sm btn-danger" href="{url_for("admin_user_action", action="disable", user=uname)}">禁用</a> '
                else:
                    body += f'<a class="btn btn-sm btn-outline-success" href="{url_for("admin_user_action", action="enable", user=uname)}">解除禁用</a> '
            if u.get("is_inspector"):
                body += f'<a class="btn btn-sm btn-outline-danger" href="{url_for("admin_user_action", action="freeze_inspector", user=uname)}">冻结巡查</a> '
            else:
                body += f'<a class="btn btn-sm btn-outline-success" href="{url_for("admin_user_action", action="restore_inspector", user=uname)}">恢复巡查资格</a> '
            body += '</div></div>'
    elif tab == "inspector_requests":
        body += '<h4>巡查员申请</h4>'
        reqs = d.get("inspector_requests", [])
        if not reqs:
            body += '<p class="text-muted">暂无申请</p>'
        else:
            for r in reqs:
                body += f'''
                  <div class="card mb-2 p-2"><div><strong>{r.get("user")}</strong> 申请时间：{r.get("time")} 状态：<strong>{r.get("status")}</strong></div>
                    <div>真实姓名：{r.get("real_name")}  身份证：{r.get("ic")}  联系：{r.get("contact")}</div>
                    <div class="mt-2">理由：{r.get("reason")}</div>
                    <div class="mt-2">
                      <a class="btn btn-sm btn-success" href="{url_for('admin_handle_inspector_apply', action='approve', user=r.get('user'))}">批准</a>
                      <a class="btn btn-sm btn-danger" href="{url_for('admin_handle_inspector_apply', action='reject', user=r.get('user'))}">拒绝</a>
                    </div>
                  </div>
                '''
    elif tab == "inspector_reports":
        return redirect(url_for("admin_inspector_reports"))
    elif tab == "copyright":
        return redirect(url_for("admin_copyrights"))
    else:
        body += '<p class="text-muted">未识别的标签</p>'

    body += '</div>'
    body += '<div class="col-md-4"><h5>控制面板</h5><div class="list-group">'
    tabs = [("overview","概览"), ("images","图片审查"), ("users","用户管理"), ("inspector_requests","巡查员申请"), ("inspector_reports","巡查报告"), ("copyright","版权申请")]
    for tname, tlabel in tabs:
        active = 'active' if tname == tab else ''
        body += f'<a class="list-group-item list-group-item-action {active}" href="{url_for("admin")}?tab={tname}">{tlabel}</a>'
    body += '</div></div></div>'
    return render(body)

# ---------------- rest of routes (detail, upload, api endpoints) should be same as previous 3.4 — kept for compatibility ---------------
# For the sake of making this file runnable, we re-include the essential simple routes (index, login, logout, register, upload, detail, report, api endpoints).
# Note: In production you may want to split into multiple modules.

@app.route("/")
def index():
    d = load_data()
    images = list(d["images"].items())
    images.sort(key=lambda x: x[1].get("created_at",""), reverse=True)
    body = '<div class="row mb-3"><div class="col-8"><h4>画廊</h4></div><div class="col-4 text-end"><small class="text-muted">本地 · 版本 %s</small></div></div><div class="row">' % d.get("version", APP_VERSION)
    for iid, im in images:
        if im.get("status") == "banned":
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

@app.route("/login", methods=("GET","POST"))
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        pwd = request.form.get("password","")
        d = load_data()
        user = d["users"].get(username)
        if not user:
            flash("用户不存在", "err"); return redirect(url_for("login"))
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
        user["failed_login"] = 0
        user["lock_until"] = None
        save_data(d)
        session["username"] = username
        flash("登录成功", "ok")
        return redirect(url_for("index"))
    body = '''
      <div class="row justify-content-center"><div class="col-md-5">
      <h4>登录</h4>
      <form method="post">
        <div class="mb-3"><input class="form-control" name="username" placeholder="用户名"></div>
        <div class="mb-3"><input class="form-control" name="password" placeholder="密码" type="password"></div>
        <button class="btn btn-primary">登录</button>
      </form>
      </div></div>
    '''
    return render(body)

@app.route("/logout")
def logout():
    session.pop("username", None)
    flash("已登出", "ok"); return redirect(url_for("index"))

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
            "lock_until": None
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

@app.route("/upload", methods=("GET","POST"))
@login_required
def upload():
    d = load_data()
    urec = d["users"].get(session["username"])
    ub = urec.get("upload_banned_until")
    if ub:
        try:
            t = datetime.datetime.fromisoformat(ub)
            if datetime.datetime.utcnow() < t:
                flash(f"上传受限至 {ub}", "err"); return redirect(url_for("index"))
        except:
            pass
    if request.method == "POST":
        if "file" not in request.files:
            flash("未选择文件", "err"); return redirect(url_for("upload"))
        f = request.files["file"]
        title = request.form.get("title","").strip()
        if f.filename == "" or not allowed_file(f.filename):
            flash("不支持的文件类型", "err"); return redirect(url_for("upload"))
        fn = secure_filename(f.filename)
        img_id = uuid.uuid4().hex
        ext = os.path.splitext(fn)[1]
        filename = f"{img_id}{ext}"
        dest = os.path.join(UPLOADS_DIR, filename)
        f.save(dest)
        d = load_data()
        d["images"][img_id] = {
            "filename": filename,
            "title": title,
            "uploader": session["username"],
            "created_at": datetime.datetime.utcnow().isoformat(),
            "upload_time": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "hash": None,
            "phash": None,
            "likes": [],
            "dislikes": [],
            "reports": [],
            "status": "processing",
            "hidden": False,
            "immune": False,
            "ban_time": None,
            "ban_reason": None,
            "copyright": {"status":"none","applicant":None,"realname":None,"id_card":None,"contact":None,"email":None,"reason":None,"review_reason":None,"approved_at":None,"similarity":0.0},
            "comments": [],
            "favorites_count": 0
        }
        save_data(d)
        t = threading.Thread(target=background_similarity_check, args=(img_id, dest), daemon=True)
        t.start()
        flash("上传接收成功，后台正在检测相似图片。", "ok")
        return redirect(url_for("index"))
    body = '''
      <div class="row justify-content-center"><div class="col-md-6">
      <h4>上传图片</h4>
      <form method="post" enctype="multipart/form-data">
        <div class="mb-3"><input class="form-control" type="file" name="file" accept="image/*"></div>
        <div class="mb-3"><input class="form-control" name="title" placeholder="标题（可选）"></div>
        <button class="btn btn-primary">上传</button>
      </form>
      </div></div>
    '''
    return render(body)

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
          <p>状态：<strong>{status}</strong></p>
          <div class="mb-3">
            <form action="{url_for('report', image_id=image_id)}" method="post">
              <div class="mb-2"><textarea class="form-control" name="reason" placeholder="举报理由（可空）"></textarea></div>
              <button class="btn btn-danger btn-sm">举报</button>
              <a class="btn btn-outline-secondary btn-sm" href="{url_for('index')}">返回</a>
            </form>
          </div>
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

@app.route("/report/<image_id>", methods=("POST",))
@login_required
def report(image_id):
    reason = request.form.get("reason", "").strip()
    d = load_data()
    im = d["images"].get(image_id)
    if not im:
        flash("图片不存在", "err"); return redirect(url_for("index"))
    rec = {"by": session["username"], "reason": reason, "at": datetime.datetime.utcnow().isoformat(), "image_id": image_id}
    im.setdefault("reports", []).append(rec)
    d.setdefault("reports", []).append(rec)
    ins_rep = {"reporter": session["username"], "image_id": image_id, "image_title": im.get("title"), "note": reason, "time": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), "status":"pending", "reviewer": None}
    d.setdefault("inspector_reports", []).append(ins_rep)
    if len(im.get("reports", [])) >= 3:
        im["status"] = "under_review"
    save_data(d)
    flash("举报已提交", "ok"); return redirect(url_for("detail", image_id=image_id))

@app.route("/inspector/mode")
@login_required
def inspector_mode():
    username = session["username"]
    d = load_data()
    u = d["users"].get(username)
    if not u or not u.get("is_inspector"):
        flash("仅巡查员可进入巡查模式", "err"); return redirect(url_for("index"))
    if u.get("frozen"):
        flash("您的巡查资格已被冻结，无法进入巡查模式", "err"); return redirect(url_for("index"))
    imgs = [(iid, im) for iid, im in d["images"].items() if im.get("status") != "banned"]
    imgs.sort(key=lambda x: x[1].get("created_at",""), reverse=True)
    body = '<h4>巡查模式（提交报告）</h4><div class="row">'
    for iid, im in imgs:
        thumb = url_for("uploaded_file", filename=im.get("filename")) if im.get("filename") else ""
        body += f'''
          <div class="col-md-6 mb-3">
            <div class="card p-2">
              <div class="d-flex">
                <div style="width:140px"><img src="{thumb}" style="max-width:140px; max-height:100px" /></div>
                <div style="flex:1; margin-left:12px">
                  <div><strong>{im.get("title")}</strong></div>
                  <div class="text-muted">上传者：{im.get("uploader")}  时间：{im.get("upload_time")}</div>
                  <div class="mt-2">
                    <form action="{url_for('submit_inspector_report', image_id=iid)}" method="post" style="display:flex; gap:8px;">
                      <input name="note" placeholder="巡查说明（可空）" class="form-control form-control-sm" />
                      <button class="btn btn-sm btn-primary">提交巡查报告</button>
                    </form>
                  </div>
                </div>
              </div>
            </div>
          </div>
        '''
    body += '</div>'
    return render(body)

@app.route("/inspector/report/<image_id>", methods=("POST",))
@login_required
def submit_inspector_report(image_id):
    username = session["username"]
    d = load_data()
    u = d["users"].get(username)
    if not u or not u.get("is_inspector"):
        flash("仅巡查员可提交巡查报告", "err"); return redirect(url_for("index"))
    if u.get("frozen"):
        flash("您的巡查资格已被冻结，无法提交巡查报告", "err"); return redirect(url_for("index"))
    note = request.form.get("note","").strip()
    im = d["images"].get(image_id)
    if not im:
        flash("图片不存在", "err"); return redirect(url_for("inspector_mode"))
    rec = {"inspector": username, "image_id": image_id, "image_title": im.get("title"), "note": note, "time": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), "status":"pending", "reviewer": None}
    d.setdefault("inspector_reports", []).append(rec)
    log_inspection_action(username, im.get("title"), "提交巡查报告")
    save_data(d)
    flash("巡查报告已提交，等待管理员审核", "ok"); return redirect(url_for("inspector_mode"))

@app.route("/admin/inspector_requests")
@admin_required
def admin_inspector_requests():
    d = load_data()
    reqs = d.get("inspector_requests", [])
    body = '<h4>巡查员申请列表</h4>'
    if not reqs:
        body += '<p class="text-muted">暂无申请</p>'
    else:
        for r in reqs:
            body += f'''
              <div class="card mb-2 p-2"><div><strong>{r.get("user")}</strong> 申请时间：{r.get("time")} 状态：<strong>{r.get("status")}</strong></div>
                <div>真实姓名：{r.get("real_name")}  身份证：{r.get("ic")}  联系：{r.get("contact")}</div>
                <div class="mt-2">理由：{r.get("reason")}</div>
                <div class="mt-2">
                  <a class="btn btn-sm btn-success" href="{url_for('admin_handle_inspector_apply', user=r.get('user'), action='approve')}">批准</a>
                  <a class="btn btn-sm btn-danger" href="{url_for('admin_handle_inspector_apply', user=r.get('user'), action='reject')}">拒绝</a>
                </div>
              </div>
            '''
    return render(body)

@app.route("/admin/inspector_apply/<action>/<user>")
@admin_required
def admin_handle_inspector_apply(action, user):
    d = load_data()
    req = None
    for r in d.get("inspector_requests", []):
        if r.get("user") == user and r.get("status") == "pending":
            req = r; break
    if not req:
        flash("申请记录不存在或已处理", "err"); return redirect(url_for("admin_inspector_requests"))
    if action == "approve":
        u = d["users"].get(user)
        if u:
            u["is_inspector"] = True
            u["frozen"] = False
            u.setdefault("notifications", []).append({"type":"inspector_approved","message":"您的巡查员申请已通过。","time":datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), "read": False})
        req["status"] = "approved"
        save_data(d)
        flash(f"{user} 已成为巡查员", "ok"); return redirect(url_for("admin_inspector_requests"))
    if action == "reject":
        req["status"] = "rejected"
        u = d["users"].get(user)
        if u:
            u.setdefault("notifications", []).append({"type":"inspector_rejected","message":"您的巡查员申请被拒绝。","time":datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), "read": False})
        save_data(d)
        flash(f"{user} 的申请已拒绝", "ok"); return redirect(url_for("admin_inspector_requests"))
    flash("未知操作", "err"); return redirect(url_for("admin_inspector_requests"))

@app.route("/admin/inspector_reports")
@admin_required
def admin_inspector_reports():
    d = load_data()
    pending = [r for r in d.get("inspector_reports", []) if r.get("status") == "pending"]
    body = '<h4>待审核巡查报告</h4>'
    if not pending:
        body += '<p class="text-muted">暂无待处理的巡查报告</p>'
    else:
        for idx, rep in enumerate(pending):
            body += f'''
              <div class="card mb-2 p-2">
                <div>图片：{rep.get("image_title")}  ID:{rep.get("image_id")}</div>
                <div>巡查员：{rep.get("inspector")}  时间：{rep.get("time")}</div>
                <div>说明：{rep.get("note")}</div>
                <div class="mt-2">
                  <a class="btn btn-sm btn-success" href="{url_for('admin_set_inspection_result', action='approved', report_index=idx)}">违规（成立）</a>
                  <a class="btn class="btn btn-sm btn-secondary" href="{url_for('admin_set_inspection_result', action='no_violation', report_index=idx)}">无违规</a>
                  <a class="btn btn-sm btn-danger" href="{url_for('admin_set_inspection_result', action='rejected', report_index=idx)}">无效举报（拒绝）</a>
                </div>
              </div>
            '''
    return render(body)

@app.route("/admin/inspector_report_action/<action>/<int:report_index>")
@admin_required
def admin_set_inspection_result(action, report_index):
    d = load_data()
    pending_all = [r for r in d.get("inspector_reports", []) if r.get("status") == "pending"]
    if report_index < 0 or report_index >= len(pending_all):
        flash("报告不存在", "err"); return redirect(url_for("admin_inspector_reports"))
    report = pending_all[report_index]
    all_reports = d.get("inspector_reports", [])
    real_index = None
    for i, r in enumerate(all_reports):
        if r is report:
            real_index = i; break
    if real_index is None:
        flash("报告索引错误", "err"); return redirect(url_for("admin_inspector_reports"))
    report = all_reports[real_index]
    if report.get("status") != "pending":
        flash("该报告已处理", "err"); return redirect(url_for("admin_inspector_reports"))
    report["status"] = action
    report["reviewer"] = session.get("username")
    inspector = report.get("inspector")
    image_id = report.get("image_id")
    image = d["images"].get(image_id)
    message = ""
    if action == "approved":
        if image:
            image["status"] = "under_review"
        update_inspector_score(inspector, correct=True)
        adjust_inspector_points(inspector, +5)
        message = f"您提交的《{report.get('image_title')}》经审核，违规属实，图片已进入审查。"
        if image:
            push_notification(image.get("uploader"), "system", f"您的图片《{image.get('title')}》因巡查员报告被送审。")
    elif action == "no_violation":
        update_inspector_score(inspector, correct=True)
        adjust_inspector_points(inspector, +5)
        message = f"您提交的《{report.get('image_title')}》经审核，图片未违规。"
    else:
        update_inspector_score(inspector, correct=False)
        adjust_inspector_points(inspector, -10)
        message = f"您提交的《{report.get('image_title')}》被判定为无效举报，请注意巡查准确性。"
    push_notification(inspector, "report_result", message, extra={"status": action, "reviewer": session.get("username")})
    log_inspection_action(inspector, report.get("image_title"), f"admin_review:{action}")
    save_data(d)
    flash("已处理该巡查报告并通知巡查员", "ok"); return redirect(url_for("admin_inspector_reports"))

@app.route("/notifications")
@login_required
def notifications():
    d = load_data()
    u = d["users"].get(session["username"])
    notes = u.get("notifications", [])
    for n in notes:
        n["read"] = True
    save_data(d)
    items = "<ul>"
    for n in reversed(notes):
        items += f"<li>[{n.get('time')}] {n.get('message')}</li>"
    items += "</ul>"
    return render(f"<h4>信息中心</h4>{items}")

@app.route("/profile/<username>", methods=("GET","POST"))
@login_required
def profile(username):
    d = load_data()
    if username not in d["users"]:
        flash("用户不存在", "err"); return redirect(url_for("index"))
    if request.method == "POST":
        if session.get("username") != username:
            flash("只能编辑自己的资料", "err"); return redirect(url_for("profile", username=username))
        sig = request.form.get("signature","").strip()
        d["users"][username]["signature"] = sig
        if "avatar" in request.files:
            f = request.files["avatar"]
            if f and allowed_file(f.filename):
                fn = secure_filename(f.filename)
                ext = os.path.splitext(fn)[1]
                aname = f"{username}_{uuid.uuid4().hex}{ext}"
                dest = os.path.join(AVATAR_DIR, aname)
                f.save(dest)
                try:
                    im = Image.open(dest)
                    im.thumbnail((256,256))
                    im.save(dest)
                except:
                    pass
                d["users"][username]["avatar"] = aname
        save_data(d)
        flash("资料已更新", "ok"); return redirect(url_for("profile", username=username))
    u = d["users"][username]
    uploads = [im for im in d["images"].values() if im.get("uploader") == username]
    uploaded_count = len(uploads)
    signature = u.get("signature","")
    avatar_url = url_for('avatar_file', filename=u.get("avatar")) if u.get("avatar") else None
    favorites = u.get("favorites", [])
    fav_thumbs = ""
    for fid in favorites[:8]:
        im = d["images"].get(fid)
        if im:
            fav_thumbs += f'<img src="{url_for("uploaded_file", filename=im.get("filename"))}" style="height:84px;margin:4px;cursor:pointer" onclick="openPreview(\'{url_for("uploaded_file", filename=im.get("filename"))}\')"/>'
    body = f'''
      <div class="row">
        <div class="col-md-6">
          <h4>{username} 的资料</h4>
          <p>显示名：{u.get("display_name")}</p>
          <p>签名：{signature}</p>
          <p>注册时间：{u.get("created_at")}</p>
          <p>上传数量：{uploaded_count}</p>
          <form method="post" enctype="multipart/form-data">
            <div class="mb-2"><input class="form-control" name="signature" placeholder="签名" value="{signature}"></div>
            <div class="mb-2"><input class="form-control" type="file" name="avatar" accept="image/*"></div>
            <button class="btn btn-sm btn-primary">保存资料</button>
          </form>
        </div>
        <div class="col-md-6">
          <h5>收藏夹</h5>
          {fav_thumbs}
        </div>
      </div>
    '''
    return render(body)

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
    im["favorites_count"] = sum(1 for u in d["users"].values() if image_id in u.get("favorites", []))
    save_data(d)
    return jsonify({"success": True, "favorited": favorited})

# ---------------- LAUNCH ----------------
if __name__ == "__main__":
    ensure_data_and_migrate()
    app.run(host="0.0.0.0", port=5000, debug=False)

