"""
RecoverSoft Server v2
- SQLite database
- Simple token auth (no JWT conflicts)
- Three roles: superadmin, org_admin, user
- Device registration + profiles
- Location playback + search
"""

from flask import Flask, request, jsonify, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime, UTC, timedelta
from functools import wraps
import uuid, os, secrets

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///recoversoft.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db     = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# ── MODELS ───────────────────────────────────────────
class Organisation(db.Model):
    id         = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name       = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    users      = db.relationship('User', backref='org', lazy=True)
    devices    = db.relationship('Device', backref='org', lazy=True)

class User(db.Model):
    id         = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name       = db.Column(db.String(120), nullable=False)
    email      = db.Column(db.String(120), unique=True, nullable=False)
    password   = db.Column(db.String(255), nullable=False)
    role       = db.Column(db.String(20), default='user')
    org_id     = db.Column(db.String(36), db.ForeignKey('organisation.id'), nullable=True)
    contact    = db.Column(db.String(20), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    devices    = db.relationship('Device', backref='owner', lazy=True)
    sessions   = db.relationship('Session', backref='user', lazy=True)

class Session(db.Model):
    id         = db.Column(db.String(64), primary_key=True)
    user_id    = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    expires_at = db.Column(db.DateTime)

class Device(db.Model):
    id            = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id     = db.Column(db.String(64), unique=True, nullable=False)
    name          = db.Column(db.String(120), nullable=False)
    user_id       = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    org_id        = db.Column(db.String(36), db.ForeignKey('organisation.id'), nullable=True)
    contact       = db.Column(db.String(20), nullable=True)
    registered_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    locations     = db.relationship('Location', backref='device', lazy=True, order_by='Location.timestamp')

class Location(db.Model):
    id        = db.Column(db.Integer, primary_key=True, autoincrement=True)
    device_id = db.Column(db.String(64), db.ForeignKey('device.device_id'), nullable=False)
    lat       = db.Column(db.Float, nullable=False)
    lng       = db.Column(db.Float, nullable=False)
    accuracy  = db.Column(db.Float)
    source    = db.Column(db.String(20))
    battery   = db.Column(db.Integer)
    city      = db.Column(db.String(80))
    hostname  = db.Column(db.String(80))
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(UTC))

# ── INIT DB ──────────────────────────────────────────
@app.before_request
def create_tables():
    db.create_all()
    if not User.query.filter_by(role="superadmin").first():
        hashed = bcrypt.generate_password_hash("admin123").decode("utf-8")
        admin = User(
            name="Mpondo Mkhunyana",
            email="admin@recoversoft.co.za",
            password=hashed,
            role="superadmin"
        )
        db.session.add(admin)
        db.session.commit()

# ── AUTH HELPERS ─────────────────────────────────────
def create_session(user_id):
    token = secrets.token_hex(32)
    session = Session(
        id=token,
        user_id=user_id,
        expires_at=datetime.now(UTC) + timedelta(days=7)
    )
    db.session.add(session)
    db.session.commit()
    return token

def get_current_user():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return None
    session = Session.query.get(token)
    if not session:
        return None
    if session.expires_at < datetime.now(UTC):
        db.session.delete(session)
        db.session.commit()
        return None
    return User.query.get(session.user_id)

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper

def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({"error": "Unauthorized"}), 401
            if user.role not in roles:
                return jsonify({"error": "Forbidden"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

def device_to_dict(device):
    locs = device.locations
    latest = locs[-1] if locs else None
    return {
        "id": device.id,
        "device_id": device.device_id,
        "name": device.name,
        "contact": device.contact,
        "registered_at": device.registered_at.isoformat(),
        "owner": device.owner.name if device.owner else None,
        "org": device.org.name if device.org else None,
        "ping_count": len(locs),
        "last_seen": latest.timestamp.isoformat() if latest else None,
        "lat": latest.lat if latest else None,
        "lng": latest.lng if latest else None,
        "accuracy": latest.accuracy if latest else None,
        "battery": latest.battery if latest else None,
        "source": latest.source if latest else None,
        "city": latest.city if latest else None,
        "hostname": latest.hostname if latest else None,
    }

# ── AUTH ROUTES ──────────────────────────────────────
@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.json or {}
    user = User.query.filter_by(email=data.get("email")).first()
    if not user or not bcrypt.check_password_hash(user.password, data.get("password", "")):
        return jsonify({"error": "Invalid credentials"}), 401
    token = create_session(user.id)
    return jsonify({
        "token": token,
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role,
            "org": user.org.name if user.org else None
        }
    })

@app.route("/api/auth/logout", methods=["POST"])
@require_auth
def logout():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    session = Session.query.get(token)
    if session:
        db.session.delete(session)
        db.session.commit()
    return jsonify({"message": "Logged out"})

@app.route("/api/auth/me")
@require_auth
def me():
    user = get_current_user()
    return jsonify({
        "id": user.id, "name": user.name,
        "email": user.email, "role": user.role,
        "org": user.org.name if user.org else None
    })

@app.route("/api/auth/register", methods=["POST"])
@require_role("superadmin", "org_admin")
def register_user():
    caller = get_current_user()
    data = request.json or {}
    if not all(k in data for k in ["name", "email", "password", "role"]):
        return jsonify({"error": "Missing fields"}), 400
    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"error": "Email already exists"}), 400
    allowed = {"superadmin": ["superadmin","org_admin","user"], "org_admin": ["user"]}
    if data["role"] not in allowed.get(caller.role, []):
        return jsonify({"error": "Cannot create this role"}), 403
    org_id = caller.org_id if caller.role == "org_admin" else data.get("org_id")
    hashed = bcrypt.generate_password_hash(data["password"]).decode("utf-8")
    user = User(name=data["name"], email=data["email"], password=hashed,
                role=data["role"], org_id=org_id, contact=data.get("contact"))
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User created", "id": user.id}), 201

@app.route("/api/users", methods=["GET"])
@require_role("superadmin", "org_admin")
def list_users():
    caller = get_current_user()
    users = User.query.all() if caller.role == "superadmin" else User.query.filter_by(org_id=caller.org_id).all()
    return jsonify([{"id": u.id, "name": u.name, "email": u.email, "role": u.role,
                     "org": u.org.name if u.org else None} for u in users])

# ── ORG ROUTES ───────────────────────────────────────
@app.route("/api/orgs", methods=["POST"])
@require_role("superadmin")
def create_org():
    data = request.json or {}
    org = Organisation(name=data.get("name", "Unnamed"))
    db.session.add(org)
    db.session.commit()
    return jsonify({"id": org.id, "name": org.name}), 201

@app.route("/api/orgs", methods=["GET"])
@require_role("superadmin")
def list_orgs():
    return jsonify([{"id": o.id, "name": o.name,
                     "users": len(o.users), "devices": len(o.devices)}
                    for o in Organisation.query.all()])

# ── DEVICE ROUTES ─────────────────────────────────────
@app.route("/api/devices/register", methods=["POST"])
@require_role("superadmin", "org_admin")
def register_device():
    caller = get_current_user()
    data = request.json or {}
    if not all(k in data for k in ["device_id", "name", "user_id"]):
        return jsonify({"error": "Missing fields"}), 400
    if Device.query.filter_by(device_id=data["device_id"]).first():
        return jsonify({"error": "Device already registered"}), 400
    user = User.query.get(data["user_id"])
    if not user:
        return jsonify({"error": "User not found"}), 404
    if caller.role == "org_admin" and user.org_id != caller.org_id:
        return jsonify({"error": "User not in your org"}), 403
    device = Device(device_id=data["device_id"], name=data["name"],
                    user_id=data["user_id"], org_id=user.org_id,
                    contact=data.get("contact"))
    db.session.add(device)
    db.session.commit()
    return jsonify({"message": "Device registered", "id": device.id}), 201

@app.route("/api/devices", methods=["GET"])
@require_auth
def list_devices():
    user = get_current_user()
    search = request.args.get("q", "").lower()
    if user.role == "superadmin":
        devices = Device.query.all()
    elif user.role == "org_admin":
        devices = Device.query.filter_by(org_id=user.org_id).all()
    else:
        devices = Device.query.filter_by(user_id=user.id).all()
    result = [device_to_dict(d) for d in devices]
    if search:
        result = [d for d in result if search in d["device_id"].lower()
                  or search in d["name"].lower()
                  or search in (d["city"] or "").lower()]
    return jsonify(result)

@app.route("/api/devices/<device_id>/history", methods=["GET"])
@require_auth
def get_history(device_id):
    user = get_current_user()
    device = Device.query.filter_by(device_id=device_id).first()
    if not device:
        return jsonify({"error": "Not found"}), 404
    if user.role == "user" and device.user_id != user.id:
        return jsonify({"error": "Unauthorized"}), 403
    if user.role == "org_admin" and device.org_id != user.org_id:
        return jsonify({"error": "Unauthorized"}), 403
    start = request.args.get("start")
    end   = request.args.get("end")
    limit = int(request.args.get("limit", 1000))
    query = Location.query.filter_by(device_id=device_id)
    if start:
        query = query.filter(Location.timestamp >= datetime.fromisoformat(start))
    if end:
        query = query.filter(Location.timestamp <= datetime.fromisoformat(end))
    locs = query.order_by(Location.timestamp).limit(limit).all()
    return jsonify([{"lat": l.lat, "lng": l.lng, "accuracy": l.accuracy,
                     "battery": l.battery, "source": l.source,
                     "timestamp": l.timestamp.isoformat()} for l in locs])

# ── TRACKER PING ─────────────────────────────────────
@app.route("/api/ping", methods=["POST"])
def receive_ping():
    data = request.json or {}
    device_id = data.get("device_id")
    if not device_id:
        return jsonify({"error": "No device_id"}), 400
    loc = Location(device_id=device_id, lat=data.get("lat", 0), lng=data.get("lng", 0),
                   accuracy=data.get("accuracy"), source=data.get("source"),
                   battery=data.get("battery"), city=data.get("city", ""),
                   hostname=data.get("hostname", ""))
    db.session.add(loc)
    db.session.commit()
    return jsonify({"status": "ok"})

@app.route("/api/batch", methods=["POST"])
def receive_batch():
    pings = (request.json or {}).get("pings", [])
    for data in pings:
        db.session.add(Location(
            device_id=data.get("device_id", ""), lat=data.get("lat", 0),
            lng=data.get("lng", 0), accuracy=data.get("accuracy"),
            source=data.get("source"), battery=data.get("battery"),
            city=data.get("city", ""), hostname=data.get("hostname", "")
        ))
    db.session.commit()
    return jsonify({"status": "ok", "received": len(pings)})

# ── FRONTEND ─────────────────────────────────────────
@app.route("/agent")
def agent():
    return """<!DOCTYPE html><html><head><meta charset="utf-8"><title>RecoverSoft Agent</title>
<style>body{font-family:sans-serif;background:#0f1117;color:#fff;display:flex;align-items:center;
justify-content:center;height:100vh;margin:0;flex-direction:column;gap:16px;}
.dot{width:12px;height:12px;border-radius:50%;background:#22c55e;animation:pulse 2s infinite;}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}p{color:#6c7280;font-size:14px;}</style>
</head><body><div class="dot"></div><p id="s">Requesting location...</p>
<script>
const ID=localStorage.getItem('rs_id')||crypto.randomUUID();
localStorage.setItem('rs_id',ID);
async function kw(){try{await navigator.wakeLock.request('screen');}catch(e){}}
kw();document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible')kw();});
function send(lat,lng,acc){
  fetch('/api/ping',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({device_id:ID,lat,lng,accuracy:acc,source:'browser',battery:null,city:'',timestamp:new Date().toISOString()})});
  document.getElementById('s').textContent='Tracking: '+lat.toFixed(4)+', '+lng.toFixed(4)+' \xb1'+Math.round(acc)+'m';
}
navigator.geolocation.watchPosition(p=>send(p.coords.latitude,p.coords.longitude,p.coords.accuracy),
  e=>document.getElementById('s').textContent='Error: '+e.message,
  {enableHighAccuracy:true,timeout:15000,maximumAge:0});
</script></body></html>"""

@app.route("/")
def dashboard():
    return open(__file__.replace('server.py','dashboard.html')).read() if os.path.exists(__file__.replace('server.py','dashboard.html')) else DASHBOARD

DASHBOARD = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>RecoverSoft</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:-apple-system,sans-serif;background:#0f1117;color:#fff;}
#auth{position:fixed;inset:0;background:#0f1117;display:flex;align-items:center;justify-content:center;z-index:9999;}
.ab{background:#1a1d27;border:1px solid #2a2d3a;border-radius:16px;padding:40px;width:360px;}
.ab h1{font-size:24px;margin-bottom:8px;}.ab p{color:#6c7280;font-size:14px;margin-bottom:24px;}
.inp{width:100%;padding:10px 14px;background:#0f1117;border:1px solid #2a2d3a;border-radius:8px;color:#fff;font-size:14px;margin-bottom:12px;}
.btn{width:100%;padding:10px;background:#3b82f6;border:none;border-radius:8px;color:#fff;font-size:14px;font-weight:600;cursor:pointer;}
.btn:hover{background:#2563eb;}.err{color:#ef4444;font-size:13px;margin-top:8px;}
#app{display:none;height:100vh;flex-direction:column;}
header{padding:12px 20px;background:#1a1d27;border-bottom:1px solid #2a2d3a;display:flex;align-items:center;gap:12px;}
header h1{font-size:18px;font-weight:700;flex:1;}
.ub{font-size:12px;color:#6c7280;background:#22253a;padding:4px 10px;border-radius:99px;}
.rb{font-size:11px;font-weight:600;padding:3px 8px;border-radius:99px;}
.r-superadmin{background:#1e3a5f;color:#60a5fa;}.r-org_admin{background:#14532d;color:#22c55e;}.r-user{background:#3f3a14;color:#facc15;}
.layout{display:flex;flex:1;overflow:hidden;}
#sidebar{width:300px;background:#1a1d27;border-right:1px solid #2a2d3a;overflow-y:auto;flex-shrink:0;display:flex;flex-direction:column;}
.sh{padding:12px 16px;border-bottom:1px solid #2a2d3a;flex-shrink:0;}
.si{width:100%;padding:8px 12px;background:#0f1117;border:1px solid #2a2d3a;border-radius:8px;color:#fff;font-size:13px;margin-bottom:8px;}
.st{font-size:11px;font-weight:600;color:#6c7280;text-transform:uppercase;letter-spacing:0.05em;}
#dl{flex:1;overflow-y:auto;}
.dc{padding:14px 16px;border-bottom:1px solid #2a2d3a;cursor:pointer;transition:background 0.15s;}
.dc:hover{background:#22253a;}.dc.active{background:#22253a;border-left:3px solid #3b82f6;}
.dn{font-weight:600;font-size:13px;margin-bottom:4px;}.dm{font-size:11px;color:#6c7280;line-height:1.6;}
.bb{height:3px;background:#2a2d3a;border-radius:2px;margin-top:6px;}
.bf{height:100%;border-radius:2px;transition:width 0.3s;}
.lv{width:6px;height:6px;border-radius:50%;background:#22c55e;display:inline-block;animation:p 2s infinite;margin-right:4px;}
@keyframes p{0%,100%{opacity:1}50%{opacity:0.4}}
#mc{flex:1;position:relative;}#map{width:100%;height:100%;}
#pb{position:absolute;bottom:0;left:0;right:0;background:rgba(26,29,39,0.95);border-top:1px solid #2a2d3a;padding:12px 16px;display:none;z-index:1000;}
.pbh{display:flex;align-items:center;gap:12px;margin-bottom:8px;}.pbh h3{font-size:13px;flex:1;}
.pbb{padding:4px 12px;border:none;border-radius:6px;background:#3b82f6;color:#fff;font-size:12px;cursor:pointer;}
.pbb.s{background:#ef4444;}
#pbs{width:100%;accent-color:#3b82f6;}#pbt{font-size:11px;color:#6c7280;margin-top:4px;text-align:center;}
#ip{position:absolute;top:16px;right:16px;background:#1a1d27;border:1px solid #2a2d3a;border-radius:12px;padding:16px;width:220px;z-index:1000;display:none;}
#ip h3{font-size:13px;margin-bottom:8px;}.ir{display:flex;justify-content:space-between;font-size:11px;color:#6c7280;margin:3px 0;}
.ir span:last-child{color:#fff;}.nd{padding:40px 16px;text-align:center;color:#6c7280;font-size:13px;}
</style>
</head>
<body>
<div id="auth">
  <div class="ab">
    <h1>RecoverSoft</h1>
    <p>Sign in to your account</p>
    <input class="inp" id="em" type="email" placeholder="Email address">
    <input class="inp" id="pw" type="password" placeholder="Password">
    <button class="btn" onclick="login()">Sign In</button>
    <div class="err" id="ae"></div>
  </div>
</div>
<div id="app">
  <header>
    <div class="lv"></div><h1>RecoverSoft</h1>
    <span class="ub" id="un">—</span>
    <span class="rb" id="ur">—</span>
  </header>
  <div class="layout">
    <div id="sidebar">
      <div class="sh">
        <input class="si" id="sq" placeholder="🔍 Search devices..." oninput="filterD()">
        <div class="st">Tracked Devices</div>
      </div>
      <div id="dl"><div class="nd">Loading...</div></div>
    </div>
    <div id="mc">
      <div id="map"></div>
      <div id="ip">
        <h3 id="iname">Device</h3>
        <div class="ir"><span>Coords</span><span id="ic">—</span></div>
        <div class="ir"><span>Accuracy</span><span id="ia">—</span></div>
        <div class="ir"><span>Battery</span><span id="ib">—</span></div>
        <div class="ir"><span>Source</span><span id="iso">—</span></div>
        <div class="ir"><span>Last seen</span><span id="il">—</span></div>
        <div class="ir"><span>City</span><span id="ici">—</span></div>
        <div class="ir"><span>Host</span><span id="ih">—</span></div>
      </div>
      <div id="pb">
        <div class="pbh">
          <h3 id="pbn">Playback</h3>
          <button class="pbb" id="ppb" onclick="togglePb()">▶ Play</button>
          <button class="pbb s" onclick="stopPb()">✕ Close</button>
        </div>
        <input type="range" id="pbs" min="0" value="0" oninput="seekPb(this.value)">
        <div id="pbt">—</div>
      </div>
    </div>
  </div>
</div>
<script>
let tok=localStorage.getItem('rs_token');
let allD=[],marks={},hL=null,hDots=[],selId=null;
let pbH=[],pbI=0,pbPlaying=false,pbT=null,pbM=null;

const map=L.map('map').setView([-25.7479,28.2293],12);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{attribution:'© OpenStreetMap',className:'dt'}).addTo(map);
document.head.insertAdjacentHTML('beforeend','<style>.dt{filter:invert(100%) hue-rotate(180deg) brightness(95%) contrast(90%)}</style>');

async function login(){
  document.getElementById('ae').textContent='';
  try{
    const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({email:document.getElementById('em').value,password:document.getElementById('pw').value})});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Login failed');
    tok=d.token;localStorage.setItem('rs_token',tok);showApp(d.user);
  }catch(e){document.getElementById('ae').textContent=e.message;}
}

function showApp(u){
  document.getElementById('auth').style.display='none';
  document.getElementById('app').style.display='flex';
  document.getElementById('un').textContent=u.name;
  const rb=document.getElementById('ur');
  rb.textContent=u.role.replace('_',' ');rb.className='rb r-'+u.role;
  loadD();
}

async function checkAuth(){
  if(!tok)return;
  try{
    const r=await fetch('/api/auth/me',{headers:{'Authorization':'Bearer '+tok}});
    if(!r.ok){localStorage.removeItem('rs_token');return;}
    showApp(await r.json());
  }catch(e){localStorage.removeItem('rs_token');}
}

async function loadD(){
  try{
    const r=await fetch('/api/devices',{headers:{'Authorization':'Bearer '+tok}});
    if(!r.ok)return;
    allD=await r.json();renderSidebar(allD);renderMarks(allD);
  }catch(e){console.error(e);}
}

function filterD(){
  const q=document.getElementById('sq').value.toLowerCase();
  renderSidebar(allD.filter(d=>d.device_id.toLowerCase().includes(q)||d.name.toLowerCase().includes(q)||(d.city||'').toLowerCase().includes(q)||(d.owner||'').toLowerCase().includes(q)));
}

function ta(ts){
  if(!ts)return'Never';
  const d=Math.floor((Date.now()-new Date(ts))/1000);
  if(d<60)return d+'s ago';if(d<3600)return Math.floor(d/60)+'m ago';return Math.floor(d/3600)+'h ago';
}

function bc(p){if(!p)return'#6c7280';if(p>50)return'#22c55e';if(p>20)return'#f59e0b';return'#ef4444';}

function renderSidebar(devices){
  const list=document.getElementById('dl');
  if(!devices.length){list.innerHTML='<div class="nd">No devices found</div>';return;}
  list.innerHTML=devices.map(d=>`
    <div class="dc ${selId===d.device_id?'active':''}" onclick="selDev('${d.device_id}')">
      <div class="dn"><span class="lv"></span>${d.name}</div>
      <div class="dm">
        🆔 ${d.device_id.substring(0,16)}...<br>
        📍 ${d.lat?d.lat.toFixed(4):'-'}, ${d.lng?d.lng.toFixed(4):'-'}<br>
        🕐 ${ta(d.last_seen)} · 📡 ${d.source||'?'} · ±${Math.round(d.accuracy||0)}m
        ${d.city?'· '+d.city:''}${d.owner?'<br>👤 '+d.owner:''}
      </div>
      <div class="bb"><div class="bf" style="width:${d.battery||0}%;background:${bc(d.battery)}"></div></div>
      <div class="dm" style="margin-top:4px">🔋 ${d.battery??'?'}%</div>
    </div>`).join('');
}

function renderMarks(devices){
  devices.forEach(d=>{
    if(!d.lat||!d.lng)return;
    const icon=L.divIcon({className:'',html:'<div style="width:14px;height:14px;border-radius:50%;background:#3b82f6;border:2px solid white;box-shadow:0 0 0 3px rgba(59,130,246,0.4)"></div>',iconSize:[14,14],iconAnchor:[7,7]});
    if(marks[d.device_id])marks[d.device_id].setLatLng([d.lat,d.lng]);
    else marks[d.device_id]=L.marker([d.lat,d.lng],{icon}).addTo(map).on('click',()=>selDev(d.device_id));
  });
}

async function selDev(did){
  selId=did;
  const d=allD.find(x=>x.device_id===did);if(!d)return;
  map.setView([d.lat,d.lng],16);
  document.getElementById('ip').style.display='block';
  document.getElementById('iname').textContent='💻 '+d.name;
  document.getElementById('ic').textContent=`${d.lat?.toFixed(5)}, ${d.lng?.toFixed(5)}`;
  document.getElementById('ia').textContent=`±${Math.round(d.accuracy||0)}m`;
  document.getElementById('ib').textContent=`${d.battery??'?'}%`;
  document.getElementById('iso').textContent=d.source||'—';
  document.getElementById('il').textContent=ta(d.last_seen);
  document.getElementById('ici').textContent=d.city||'—';
  document.getElementById('ih').textContent=d.hostname||'—';
  const r=await fetch(`/api/devices/${did}/history`,{headers:{'Authorization':'Bearer '+tok}});
  const hist=await r.json();
  drawHist(hist);setupPb(hist,d.name);renderSidebar(allD);
}

function clrHist(){if(hL){map.removeLayer(hL);hL=null;}hDots.forEach(d=>map.removeLayer(d));hDots=[];}

function drawHist(pings){
  clrHist();if(pings.length<2)return;
  hL=L.polyline(pings.map(p=>[p.lat,p.lng]),{color:'#f59e0b',weight:2,opacity:0.7,dashArray:'4 6'}).addTo(map);
  pings.forEach((p,i)=>{
    const dot=L.circleMarker([p.lat,p.lng],{radius:i===0?5:3,fillColor:i===0?'#ef4444':'#f59e0b',color:'white',weight:1,fillOpacity:0.8}).addTo(map);
    dot.bindTooltip(ta(p.timestamp));hDots.push(dot);
  });
  map.fitBounds(hL.getBounds(),{padding:[40,40]});
}

function setupPb(hist,name){
  if(hist.length<2)return;
  pbH=hist;pbI=0;pbPlaying=false;clearInterval(pbT);
  document.getElementById('pb').style.display='block';
  const s=document.getElementById('pbs');s.max=hist.length-1;s.value=0;
  document.getElementById('pbn').textContent='▶ '+name;updatePb(0);
}

function updatePb(i){
  const p=pbH[i];if(!p)return;
  document.getElementById('pbt').textContent=new Date(p.timestamp).toLocaleString()+' · ±'+Math.round(p.accuracy||0)+'m · 🔋'+(p.battery??'?')+'%';
  document.getElementById('pbs').value=i;
  if(pbM)map.removeLayer(pbM);
  pbM=L.circleMarker([p.lat,p.lng],{radius:8,fillColor:'#fff',color:'#3b82f6',weight:3,fillOpacity:1}).addTo(map);
  map.panTo([p.lat,p.lng]);
}

function togglePb(){
  pbPlaying=!pbPlaying;
  document.getElementById('ppb').textContent=pbPlaying?'⏸ Pause':'▶ Play';
  if(pbPlaying){pbT=setInterval(()=>{if(pbI>=pbH.length-1){pbPlaying=false;clearInterval(pbT);document.getElementById('ppb').textContent='▶ Play';return;}pbI++;updatePb(pbI);},500);}
  else clearInterval(pbT);
}

function seekPb(v){pbI=parseInt(v);updatePb(pbI);}

function stopPb(){
  pbPlaying=false;clearInterval(pbT);
  document.getElementById('pb').style.display='none';
  if(pbM){map.removeLayer(pbM);pbM=null;}
}

checkAuth();
setInterval(loadD,30000);
document.addEventListener('keydown',e=>{if(e.key==='Enter'&&document.getElementById('auth').style.display!=='none')login();});
</script>
</body>
</html>"""

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    print("RecoverSoft v2 running on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
