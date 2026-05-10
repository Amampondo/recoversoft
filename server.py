"""
RecoverSoft Server v2
- SQLite database (upgrades to PostgreSQL)
- JWT authentication
- Three roles: superadmin, org_admin, user
- Device registration + profiles
- Location playback
- Search by device ID
"""

from flask import Flask, request, jsonify, render_template_string, g
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required,
    get_jwt_identity, get_jwt
)
from flask_bcrypt import Bcrypt
from datetime import datetime, UTC, timedelta
import uuid, os, json

app = Flask(__name__)

# ── CONFIG ───────────────────────────────────────────
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'sqlite:///recoversoft.db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET', 'change-this-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)

db      = SQLAlchemy(app)
jwt     = JWTManager(app)
bcrypt  = Bcrypt(app)

# ── MODELS ───────────────────────────────────────────
class Organisation(db.Model):
    id         = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name       = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    users      = db.relationship('User', backref='org', lazy=True)
    devices    = db.relationship('Device', backref='org', lazy=True)

class User(db.Model):
    id          = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name        = db.Column(db.String(120), nullable=False)
    email       = db.Column(db.String(120), unique=True, nullable=False)
    password    = db.Column(db.String(255), nullable=False)
    role        = db.Column(db.String(20), default='user')  # superadmin, org_admin, user
    org_id      = db.Column(db.String(36), db.ForeignKey('organisation.id'), nullable=True)
    contact     = db.Column(db.String(20), nullable=True)
    created_at  = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    devices     = db.relationship('Device', backref='owner', lazy=True)

class Device(db.Model):
    id          = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id   = db.Column(db.String(36), unique=True, nullable=False)  # tracker ID
    name        = db.Column(db.String(120), nullable=False)
    user_id     = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    org_id      = db.Column(db.String(36), db.ForeignKey('organisation.id'), nullable=True)
    contact     = db.Column(db.String(20), nullable=True)
    registered_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    locations   = db.relationship('Location', backref='device', lazy=True,
                                  order_by='Location.timestamp')

class Location(db.Model):
    id         = db.Column(db.Integer, primary_key=True, autoincrement=True)
    device_id  = db.Column(db.String(36), db.ForeignKey('device.device_id'), nullable=False)
    lat        = db.Column(db.Float, nullable=False)
    lng        = db.Column(db.Float, nullable=False)
    accuracy   = db.Column(db.Float)
    source     = db.Column(db.String(20))
    battery    = db.Column(db.Integer)
    city       = db.Column(db.String(80))
    hostname   = db.Column(db.String(80))
    timestamp  = db.Column(db.DateTime, default=lambda: datetime.now(UTC))

# ── HELPERS ──────────────────────────────────────────
def current_user():
    identity = get_jwt_identity()
    return User.query.get(identity)

def require_role(*roles):
    def decorator(f):
        from functools import wraps
        @wraps(f)
        @jwt_required()
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user or user.role not in roles:
                return jsonify({"error": "Unauthorized"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

def device_to_dict(device, latest_only=True):
    locs = device.locations
    latest = locs[-1] if locs else None
    d = {
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
    }
    return d

# ── AUTH ROUTES ──────────────────────────────────────
@app.route("/api/auth/register", methods=["POST"])
@require_role("superadmin")
def register_user():
    """Superadmin creates any user. Org admin creates users in their org."""
    data = request.json
    caller = current_user()

    # Validate
    if not all(k in data for k in ["name", "email", "password", "role"]):
        return jsonify({"error": "Missing fields"}), 400

    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"error": "Email already exists"}), 400

    # Role restrictions
    allowed_roles = {
        "superadmin": ["superadmin", "org_admin", "user"],
        "org_admin":  ["user"],
        "user":       []
    }
    if data["role"] not in allowed_roles.get(caller.role, []):
        return jsonify({"error": f"Cannot create {data['role']} account"}), 403

    # Org assignment
    org_id = data.get("org_id")
    if caller.role == "org_admin":
        org_id = caller.org_id  # force to caller's org

    hashed = bcrypt.generate_password_hash(data["password"]).decode("utf-8")
    user = User(
        name=data["name"],
        email=data["email"],
        password=hashed,
        role=data["role"],
        org_id=org_id,
        contact=data.get("contact")
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User created", "id": user.id}), 201

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.json
    user = User.query.filter_by(email=data.get("email")).first()
    if not user or not bcrypt.check_password_hash(user.password, data.get("password", "")):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_access_token(
        identity=user.id,
        additional_claims={"role": user.role, "org_id": user.org_id}
    )
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

@app.route("/api/auth/me")
@jwt_required()
def me():
    user = current_user()
    return jsonify({
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role,
        "org": user.org.name if user.org else None
    })

# ── ORGANISATION ROUTES ───────────────────────────────
@app.route("/api/orgs", methods=["POST"])
@require_role("superadmin")
def create_org():
    data = request.json
    org = Organisation(name=data["name"])
    db.session.add(org)
    db.session.commit()
    return jsonify({"id": org.id, "name": org.name}), 201

@app.route("/api/orgs", methods=["GET"])
@require_role("superadmin")
def list_orgs():
    orgs = Organisation.query.all()
    return jsonify([{"id": o.id, "name": o.name, "users": len(o.users), "devices": len(o.devices)} for o in orgs])

# ── DEVICE ROUTES ─────────────────────────────────────
@app.route("/api/devices/register", methods=["POST"])
@require_role("superadmin", "org_admin")
def register_device():
    """Admin registers a device and links it to a user."""
    data = request.json
    caller = current_user()

    if not all(k in data for k in ["device_id", "name", "user_id"]):
        return jsonify({"error": "Missing fields"}), 400

    if Device.query.filter_by(device_id=data["device_id"]).first():
        return jsonify({"error": "Device already registered"}), 400

    user = User.query.get(data["user_id"])
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Org admin can only register to users in their org
    if caller.role == "org_admin" and user.org_id != caller.org_id:
        return jsonify({"error": "User not in your organisation"}), 403

    device = Device(
        device_id=data["device_id"],
        name=data["name"],
        user_id=data["user_id"],
        org_id=user.org_id,
        contact=data.get("contact")
    )
    db.session.add(device)
    db.session.commit()
    return jsonify({"message": "Device registered", "id": device.id}), 201

@app.route("/api/devices", methods=["GET"])
@jwt_required()
def list_devices():
    """Return devices based on role."""
    user = current_user()
    search = request.args.get("q", "").lower()

    if user.role == "superadmin":
        devices = Device.query.all()
    elif user.role == "org_admin":
        devices = Device.query.filter_by(org_id=user.org_id).all()
    else:
        devices = Device.query.filter_by(user_id=user.id).all()

    result = [device_to_dict(d) for d in devices]

    # Search filter
    if search:
        result = [d for d in result if
                  search in d["device_id"].lower() or
                  search in d["name"].lower() or
                  search in (d["city"] or "").lower()]

    return jsonify(result)

@app.route("/api/devices/<device_id>", methods=["GET"])
@jwt_required()
def get_device(device_id):
    user = current_user()
    device = Device.query.filter_by(device_id=device_id).first()
    if not device:
        return jsonify({"error": "Device not found"}), 404

    # Access control
    if user.role == "user" and device.user_id != user.id:
        return jsonify({"error": "Unauthorized"}), 403
    if user.role == "org_admin" and device.org_id != user.org_id:
        return jsonify({"error": "Unauthorized"}), 403

    return jsonify(device_to_dict(device))

@app.route("/api/devices/<device_id>/history", methods=["GET"])
@jwt_required()
def get_history(device_id):
    """Get location history with optional time range."""
    user = current_user()
    device = Device.query.filter_by(device_id=device_id).first()
    if not device:
        return jsonify({"error": "Device not found"}), 404

    # Access control
    if user.role == "user" and device.user_id != user.id:
        return jsonify({"error": "Unauthorized"}), 403
    if user.role == "org_admin" and device.org_id != user.org_id:
        return jsonify({"error": "Unauthorized"}), 403

    # Optional time range for playback
    start = request.args.get("start")
    end   = request.args.get("end")
    limit = int(request.args.get("limit", 1000))

    query = Location.query.filter_by(device_id=device_id)
    if start:
        query = query.filter(Location.timestamp >= datetime.fromisoformat(start))
    if end:
        query = query.filter(Location.timestamp <= datetime.fromisoformat(end))

    locs = query.order_by(Location.timestamp).limit(limit).all()
    return jsonify([{
        "lat": l.lat, "lng": l.lng,
        "accuracy": l.accuracy,
        "battery": l.battery,
        "source": l.source,
        "timestamp": l.timestamp.isoformat()
    } for l in locs])

# ── TRACKER PING ROUTES ───────────────────────────────
@app.route("/api/ping", methods=["POST"])
def receive_ping():
    data = request.json
    device_id = data.get("device_id")
    if not device_id:
        return jsonify({"error": "No device_id"}), 400

    # Check device is registered
    device = Device.query.filter_by(device_id=device_id).first()
    if not device:
        # Store anyway — admin can register later
        pass

    loc = Location(
        device_id=device_id,
        lat=data.get("lat", 0),
        lng=data.get("lng", 0),
        accuracy=data.get("accuracy"),
        source=data.get("source"),
        battery=data.get("battery"),
        city=data.get("city", ""),
        hostname=data.get("hostname", "")
    )
    db.session.add(loc)
    db.session.commit()
    return jsonify({"status": "ok"})

@app.route("/api/batch", methods=["POST"])
def receive_batch():
    pings = request.json.get("pings", [])
    for data in pings:
        loc = Location(
            device_id=data.get("device_id"),
            lat=data.get("lat", 0),
            lng=data.get("lng", 0),
            accuracy=data.get("accuracy"),
            source=data.get("source"),
            battery=data.get("battery"),
            city=data.get("city", ""),
            hostname=data.get("hostname", "")
        )
        db.session.add(loc)
    db.session.commit()
    return jsonify({"status": "ok", "received": len(pings)})

# ── DASHBOARD ─────────────────────────────────────────
@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD)

@app.route("/agent")
def agent():
    return render_template_string(AGENT)

# ── INIT DB + DEFAULT SUPERADMIN ─────────────────────
def init_db():
    with app.app_context():
        db.create_all()
        # Create default superadmin if none exists
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
            print("✓ Default superadmin created")
            print("  Email: admin@recoversoft.co.za")
            print("  Password: admin123")
            print("  CHANGE THIS PASSWORD IMMEDIATELY")

# ── FRONTEND ─────────────────────────────────────────
AGENT = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>RecoverSoft Agent</title>
<style>
body { font-family: sans-serif; background:#0f1117; color:#fff;
       display:flex; align-items:center; justify-content:center;
       height:100vh; margin:0; flex-direction:column; gap:16px; }
.dot { width:12px; height:12px; border-radius:50%; background:#22c55e;
       animation:pulse 2s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
p { color:#6c7280; font-size:14px; }
</style>
</head>
<body>
<div class="dot"></div>
<p id="status">Requesting location...</p>
<script>
const ID = localStorage.getItem('rs_id') || crypto.randomUUID();
localStorage.setItem('rs_id', ID);

async function keepAwake() {
  try { await navigator.wakeLock.request('screen'); } catch(e) {}
}
keepAwake();
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') keepAwake();
});

function send(lat, lng, acc) {
  fetch('/api/ping', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      device_id: ID, lat, lng,
      accuracy: acc, source:'browser',
      battery: null, city:'',
      timestamp: new Date().toISOString()
    })
  });
  document.getElementById('status').textContent =
    'Tracking: ' + lat.toFixed(4) + ', ' + lng.toFixed(4) + ' ±' + Math.round(acc) + 'm';
}

navigator.geolocation.watchPosition(
  p => send(p.coords.latitude, p.coords.longitude, p.coords.accuracy),
  e => document.getElementById('status').textContent = 'Error: ' + e.message,
  {enableHighAccuracy:true, timeout:15000, maximumAge:0}
);
</script>
</body>
</html>
"""

DASHBOARD = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>RecoverSoft Dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:-apple-system,sans-serif; background:#0f1117; color:#fff; }

/* AUTH SCREEN */
#auth {
  position:fixed; inset:0; background:#0f1117;
  display:flex; align-items:center; justify-content:center;
  z-index:9999;
}
.auth-box {
  background:#1a1d27; border:1px solid #2a2d3a;
  border-radius:16px; padding:40px; width:360px;
}
.auth-box h1 { font-size:24px; margin-bottom:8px; color:#fff; }
.auth-box p { color:#6c7280; font-size:14px; margin-bottom:24px; }
.input {
  width:100%; padding:10px 14px; background:#0f1117;
  border:1px solid #2a2d3a; border-radius:8px;
  color:#fff; font-size:14px; margin-bottom:12px;
}
.btn {
  width:100%; padding:10px; background:#3b82f6;
  border:none; border-radius:8px; color:#fff;
  font-size:14px; font-weight:600; cursor:pointer;
}
.btn:hover { background:#2563eb; }
.error { color:#ef4444; font-size:13px; margin-top:8px; }

/* MAIN APP */
#app { display:none; height:100vh; flex-direction:column; }
header {
  padding:12px 20px; background:#1a1d27;
  border-bottom:1px solid #2a2d3a;
  display:flex; align-items:center; gap:12px;
}
header h1 { font-size:18px; font-weight:700; flex:1; }
.user-badge {
  font-size:12px; color:#6c7280;
  background:#22253a; padding:4px 10px;
  border-radius:99px;
}
.role-badge {
  font-size:11px; font-weight:600;
  padding:3px 8px; border-radius:99px;
}
.role-superadmin { background:#1e3a5f; color:#60a5fa; }
.role-org_admin  { background:#14532d; color:#22c55e; }
.role-user       { background:#3f3a14; color:#facc15; }

.layout { display:flex; flex:1; overflow:hidden; }
#sidebar {
  width:300px; background:#1a1d27;
  border-right:1px solid #2a2d3a;
  overflow-y:auto; flex-shrink:0;
  display:flex; flex-direction:column;
}
.sidebar-header {
  padding:12px 16px;
  border-bottom:1px solid #2a2d3a;
  flex-shrink:0;
}
.search-input {
  width:100%; padding:8px 12px; background:#0f1117;
  border:1px solid #2a2d3a; border-radius:8px;
  color:#fff; font-size:13px; margin-bottom:8px;
}
.sidebar-title {
  font-size:11px; font-weight:600; color:#6c7280;
  text-transform:uppercase; letter-spacing:0.05em;
}
#device-list { flex:1; overflow-y:auto; }
.device-card {
  padding:14px 16px; border-bottom:1px solid #2a2d3a;
  cursor:pointer; transition:background 0.15s;
}
.device-card:hover { background:#22253a; }
.device-card.active { background:#22253a; border-left:3px solid #3b82f6; }
.device-name { font-weight:600; font-size:13px; margin-bottom:4px; }
.device-meta { font-size:11px; color:#6c7280; line-height:1.6; }
.battery-bar { height:3px; background:#2a2d3a; border-radius:2px; margin-top:6px; }
.battery-fill { height:100%; border-radius:2px; transition:width 0.3s; }
.dot-live { width:6px; height:6px; border-radius:50%; background:#22c55e;
            display:inline-block; animation:pulse 2s infinite; margin-right:4px; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }

#map-container { flex:1; position:relative; }
#map { width:100%; height:100%; }

/* PLAYBACK */
#playback {
  position:absolute; bottom:0; left:0; right:0;
  background:rgba(26,29,39,0.95);
  border-top:1px solid #2a2d3a;
  padding:12px 16px; display:none;
  z-index:1000;
}
.playback-header {
  display:flex; align-items:center;
  gap:12px; margin-bottom:8px;
}
.playback-header h3 { font-size:13px; flex:1; }
.pb-btn {
  padding:4px 12px; border:none; border-radius:6px;
  background:#3b82f6; color:#fff; font-size:12px;
  cursor:pointer;
}
.pb-btn.stop { background:#ef4444; }
#pb-slider { width:100%; accent-color:#3b82f6; }
#pb-time { font-size:11px; color:#6c7280; margin-top:4px; text-align:center; }

/* INFO PANEL */
#info-panel {
  position:absolute; top:16px; right:16px;
  background:#1a1d27; border:1px solid #2a2d3a;
  border-radius:12px; padding:16px; width:220px;
  z-index:1000; display:none;
}
#info-panel h3 { font-size:13px; margin-bottom:8px; }
.info-row {
  display:flex; justify-content:space-between;
  font-size:11px; color:#6c7280; margin:3px 0;
}
.info-row span:last-child { color:#fff; }
.no-devices {
  padding:40px 16px; text-align:center;
  color:#6c7280; font-size:13px;
}
</style>
</head>
<body>

<!-- AUTH -->
<div id="auth">
  <div class="auth-box">
    <h1>RecoverSoft</h1>
    <p>Sign in to your account</p>
    <input class="input" id="email" type="email" placeholder="Email address">
    <input class="input" id="password" type="password" placeholder="Password">
    <button class="btn" onclick="login()">Sign In</button>
    <div class="error" id="auth-error"></div>
  </div>
</div>

<!-- MAIN APP -->
<div id="app">
  <header>
    <div class="dot-live"></div>
    <h1>RecoverSoft</h1>
    <span class="user-badge" id="user-name">—</span>
    <span class="role-badge" id="user-role">—</span>
  </header>
  <div class="layout">
    <div id="sidebar">
      <div class="sidebar-header">
        <input class="search-input" id="search" placeholder="🔍 Search devices..."
               oninput="filterDevices()">
        <div class="sidebar-title">Tracked Devices</div>
      </div>
      <div id="device-list">
        <div class="no-devices">Loading...</div>
      </div>
    </div>
    <div id="map-container">
      <div id="map"></div>
      <div id="info-panel">
        <h3 id="info-name">Device</h3>
        <div class="info-row"><span>Coords</span><span id="info-coords">—</span></div>
        <div class="info-row"><span>Accuracy</span><span id="info-accuracy">—</span></div>
        <div class="info-row"><span>Battery</span><span id="info-battery">—</span></div>
        <div class="info-row"><span>Source</span><span id="info-source">—</span></div>
        <div class="info-row"><span>Last seen</span><span id="info-lastseen">—</span></div>
        <div class="info-row"><span>City</span><span id="info-city">—</span></div>
        <div class="info-row"><span>Host</span><span id="info-host">—</span></div>
      </div>
      <div id="playback">
        <div class="playback-header">
          <h3 id="pb-device-name">Playback</h3>
          <button class="pb-btn" id="pb-play-btn" onclick="togglePlayback()">▶ Play</button>
          <button class="pb-btn stop" onclick="stopPlayback()">✕ Close</button>
        </div>
        <input type="range" id="pb-slider" min="0" value="0" oninput="seekPlayback(this.value)">
        <div id="pb-time">—</div>
      </div>
    </div>
  </div>
</div>

<script>
let token = localStorage.getItem('rs_token');
let allDevices = [];
let markers = {};
let historyLayer = null;
let historyDots = [];
let selectedDeviceId = null;
let pbHistory = [];
let pbIndex = 0;
let pbPlaying = false;
let pbTimer = null;
let pbMarker = null;

const map = L.map('map').setView([-25.7479, 28.2293], 12);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
  attribution:'© OpenStreetMap', className:'dark-tiles'
}).addTo(map);
document.head.insertAdjacentHTML('beforeend',
  '<style>.dark-tiles{filter:invert(100%) hue-rotate(180deg) brightness(95%) contrast(90%)}</style>');

// ── AUTH ──────────────────────────────────────────
async function login() {
  const email    = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  document.getElementById('auth-error').textContent = '';
  try {
    const res = await fetch('/api/auth/login', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({email, password})
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Login failed');
    token = data.token;
    localStorage.setItem('rs_token', token);
    showApp(data.user);
  } catch(e) {
    document.getElementById('auth-error').textContent = e.message;
  }
}

function showApp(user) {
  document.getElementById('auth').style.display = 'none';
  document.getElementById('app').style.display = 'flex';
  document.getElementById('user-name').textContent = user.name;
  const rb = document.getElementById('user-role');
  rb.textContent = user.role.replace('_', ' ');
  rb.className = 'role-badge role-' + user.role;
  loadDevices();
}

async function checkAuth() {
  if (!token) return;
  try {
    const res = await fetch('/api/auth/me', {
      headers:{'Authorization':'Bearer ' + token}
    });
    if (!res.ok) { localStorage.removeItem('rs_token'); return; }
    const user = await res.json();
    showApp(user);
  } catch(e) { localStorage.removeItem('rs_token'); }
}

// ── DEVICES ───────────────────────────────────────
async function loadDevices() {
  try {
    const res = await fetch('/api/devices', {
      headers:{'Authorization':'Bearer ' + token}
    });
    allDevices = await res.json();
    renderSidebar(allDevices);
    renderMarkers(allDevices);
  } catch(e) { console.error(e); }
}

function filterDevices() {
  const q = document.getElementById('search').value.toLowerCase();
  const filtered = allDevices.filter(d =>
    d.device_id.toLowerCase().includes(q) ||
    d.name.toLowerCase().includes(q) ||
    (d.city||'').toLowerCase().includes(q) ||
    (d.owner||'').toLowerCase().includes(q)
  );
  renderSidebar(filtered);
}

function timeAgo(ts) {
  if (!ts) return 'Never';
  const diff = Math.floor((Date.now() - new Date(ts)) / 1000);
  if (diff < 60) return diff + 's ago';
  if (diff < 3600) return Math.floor(diff/60) + 'm ago';
  return Math.floor(diff/3600) + 'h ago';
}

function battColor(p) {
  if (!p) return '#6c7280';
  if (p > 50) return '#22c55e';
  if (p > 20) return '#f59e0b';
  return '#ef4444';
}

function renderSidebar(devices) {
  const list = document.getElementById('device-list');
  if (!devices.length) {
    list.innerHTML = '<div class="no-devices">No devices found</div>';
    return;
  }
  list.innerHTML = devices.map(d => `
    <div class="device-card ${selectedDeviceId===d.device_id?'active':''}"
         onclick="selectDevice('${d.device_id}')">
      <div class="device-name">
        <span class="dot-live"></span>${d.name}
      </div>
      <div class="device-meta">
        🆔 ${d.device_id.substring(0,16)}...<br>
        📍 ${d.lat?d.lat.toFixed(4):'-'}, ${d.lng?d.lng.toFixed(4):'-'}<br>
        🕐 ${timeAgo(d.last_seen)} · 📡 ${d.source||'?'} · ±${Math.round(d.accuracy||0)}m
        ${d.city ? '· ' + d.city : ''}
        ${d.owner ? '<br>👤 ' + d.owner : ''}
      </div>
      <div class="battery-bar">
        <div class="battery-fill" style="width:${d.battery||0}%;background:${battColor(d.battery)}"></div>
      </div>
      <div class="device-meta" style="margin-top:4px">🔋 ${d.battery??'?'}%</div>
    </div>
  `).join('');
}

function renderMarkers(devices) {
  devices.forEach(d => {
    if (!d.lat || !d.lng) return;
    const icon = L.divIcon({
      className:'',
      html:`<div style="width:14px;height:14px;border-radius:50%;
            background:#3b82f6;border:2px solid white;
            box-shadow:0 0 0 3px rgba(59,130,246,0.4)"></div>`,
      iconSize:[14,14], iconAnchor:[7,7]
    });
    if (markers[d.device_id]) {
      markers[d.device_id].setLatLng([d.lat, d.lng]);
    } else {
      markers[d.device_id] = L.marker([d.lat,d.lng],{icon})
        .addTo(map).on('click', () => selectDevice(d.device_id));
    }
  });
}

// ── SELECT DEVICE ─────────────────────────────────
async function selectDevice(device_id) {
  selectedDeviceId = device_id;
  const d = allDevices.find(x => x.device_id === device_id);
  if (!d) return;

  map.setView([d.lat, d.lng], 16);

  // Info panel
  const panel = document.getElementById('info-panel');
  panel.style.display = 'block';
  document.getElementById('info-name').textContent = '💻 ' + d.name;
  document.getElementById('info-coords').textContent = `${d.lat?.toFixed(5)}, ${d.lng?.toFixed(5)}`;
  document.getElementById('info-accuracy').textContent = `±${Math.round(d.accuracy||0)}m`;
  document.getElementById('info-battery').textContent = `${d.battery??'?'}%`;
  document.getElementById('info-source').textContent = d.source||'—';
  document.getElementById('info-lastseen').textContent = timeAgo(d.last_seen);
  document.getElementById('info-city').textContent = d.city||'—';
  document.getElementById('info-host').textContent = d.hostname||'—';

  // Load history
  const res = await fetch(`/api/devices/${device_id}/history`, {
    headers:{'Authorization':'Bearer ' + token}
  });
  const history = await res.json();
  drawHistory(history);
  setupPlayback(history, d.name);
  renderSidebar(allDevices);
}

// ── HISTORY TRAIL ────────────────────────────────
function clearHistory() {
  if (historyLayer) { map.removeLayer(historyLayer); historyLayer = null; }
  historyDots.forEach(d => map.removeLayer(d));
  historyDots = [];
}

function drawHistory(pings) {
  clearHistory();
  if (pings.length < 2) return;
  const coords = pings.map(p => [p.lat, p.lng]);
  historyLayer = L.polyline(coords, {
    color:'#f59e0b', weight:2, opacity:0.7, dashArray:'4 6'
  }).addTo(map);
  pings.forEach((p, i) => {
    const dot = L.circleMarker([p.lat, p.lng], {
      radius: i===0 ? 5 : 3,
      fillColor: i===0 ? '#ef4444' : '#f59e0b',
      color:'white', weight:1, fillOpacity:0.8
    }).addTo(map);
    dot.bindTooltip(timeAgo(p.timestamp));
    historyDots.push(dot);
  });
  map.fitBounds(historyLayer.getBounds(), {padding:[40,40]});
}

// ── PLAYBACK ─────────────────────────────────────
function setupPlayback(history, name) {
  if (history.length < 2) return;
  pbHistory = history;
  pbIndex = 0;
  pbPlaying = false;
  clearInterval(pbTimer);

  const panel = document.getElementById('playback');
  const slider = document.getElementById('pb-slider');
  panel.style.display = 'block';
  slider.max = history.length - 1;
  slider.value = 0;
  document.getElementById('pb-device-name').textContent = '▶ ' + name;
  updatePbTime(0);
}

function updatePbTime(index) {
  const p = pbHistory[index];
  if (!p) return;
  document.getElementById('pb-time').textContent =
    new Date(p.timestamp).toLocaleString() +
    ' · ±' + Math.round(p.accuracy||0) + 'm · 🔋' + (p.battery??'?') + '%';
  document.getElementById('pb-slider').value = index;

  // Move playback marker
  if (pbMarker) map.removeLayer(pbMarker);
  pbMarker = L.circleMarker([p.lat, p.lng], {
    radius:8, fillColor:'#ffffff', color:'#3b82f6',
    weight:3, fillOpacity:1
  }).addTo(map);
  map.panTo([p.lat, p.lng]);
}

function togglePlayback() {
  pbPlaying = !pbPlaying;
  document.getElementById('pb-play-btn').textContent = pbPlaying ? '⏸ Pause' : '▶ Play';
  if (pbPlaying) {
    pbTimer = setInterval(() => {
      if (pbIndex >= pbHistory.length - 1) {
        pbPlaying = false;
        clearInterval(pbTimer);
        document.getElementById('pb-play-btn').textContent = '▶ Play';
        return;
      }
      pbIndex++;
      updatePbTime(pbIndex);
    }, 500);
  } else {
    clearInterval(pbTimer);
  }
}

function seekPlayback(val) {
  pbIndex = parseInt(val);
  updatePbTime(pbIndex);
}

function stopPlayback() {
  pbPlaying = false;
  clearInterval(pbTimer);
  document.getElementById('playback').style.display = 'none';
  if (pbMarker) { map.removeLayer(pbMarker); pbMarker = null; }
}

// ── INIT ─────────────────────────────────────────
checkAuth();
setInterval(loadDevices, 30000);

// Enter key on login
document.addEventListener('keydown', e => {
  if (e.key === 'Enter' && document.getElementById('auth').style.display !== 'none') {
    login();
  }
});
</script>
</body>
</html>
"""

if __name__ == "__main__":
    init_db()
    print("RecoverSoft v2 running on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
