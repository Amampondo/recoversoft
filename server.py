#!/usr/bin/env python3
"""
RecoverSoft Server
- Receives location pings from tracked laptops
- Serves live map dashboard
"""

from flask import Flask, request, jsonify, render_template_string
import json, os
from datetime import datetime

app = Flask(__name__)
DB_FILE = "locations.json"

def load_db():
    if os.path.exists(DB_FILE):
        with open(DB_FILE) as f:
            return json.load(f)
    return {}

def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)

# ── API ──────────────────────────────────────────────
@app.route("/api/ping", methods=["POST"])
def receive_ping():
    data = request.json
    device_id = data.get("device_id", "unknown")
    db = load_db()
    if device_id not in db:
        db[device_id] = []
    db[device_id].append(data)
    db[device_id] = db[device_id][-1000:]  # keep last 1000 pings
    save_db(db)
    return jsonify({"status": "ok"})

@app.route("/api/batch", methods=["POST"])
def receive_batch():
    pings = request.json.get("pings", [])
    db = load_db()
    for data in pings:
        device_id = data.get("device_id", "unknown")
        if device_id not in db:
            db[device_id] = []
        db[device_id].append(data)
    save_db(db)
    return jsonify({"status": "ok", "received": len(pings)})

@app.route("/agent")
def agent():
    """
    Runs on the tracked laptop in a browser.
    Uses browser W3C Geolocation API (Google's WiFi DB)
    for accurate location — sends to server automatically.
    """
    return render_template_string(AGENT_PAGE)

AGENT_PAGE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>RecoverSoft Agent</title>
<style>
  body { font-family: sans-serif; background: #0f1117; color: #fff;
         display: flex; align-items: center; justify-content: center;
         height: 100vh; margin: 0; flex-direction: column; gap: 16px; }
  .dot { width: 12px; height: 12px; border-radius: 50%; background: #22c55e;
         animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
  p { color: #6c7280; font-size: 14px; }
</style>
</head>
<body>
<div class="dot"></div>
<p id="status">Requesting location permission...</p>
<script>
const DEVICE_ID = localStorage.getItem('rs_device_id') || 
                  Math.random().toString(36).substring(2);
localStorage.setItem('rs_device_id', DEVICE_ID);

function sendLocation(lat, lng, accuracy) {
  fetch('/api/ping', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      device_id: DEVICE_ID,
      lat, lng, accuracy,
      source: 'browser',
      battery: null,
      city: '',
      timestamp: new Date().toISOString()
    })
  });
  document.getElementById('status').textContent = 
    `Tracking active — ${lat.toFixed(4)}, ${lng.toFixed(4)} (±${Math.round(accuracy)}m)`;
}

function startTracking() {
  if (!navigator.geolocation) {
    document.getElementById('status').textContent = 'Geolocation not supported';
    return;
  }
  // Get location every 60 seconds
  navigator.geolocation.watchPosition(
    pos => sendLocation(pos.coords.latitude, pos.coords.longitude, pos.coords.accuracy),
    err => document.getElementById('status').textContent = 'Location denied: ' + err.message,
    { enableHighAccuracy: true, timeout: 15000, maximumAge: 60000 }
  );
}

startTracking();
</script>
</body>
</html>
"""

@app.route("/api/devices")
def get_devices():
    db = load_db()
    devices = []
    for device_id, pings in db.items():
        if pings:
            latest = pings[-1]
            devices.append({
                "device_id": device_id,
                "lat": latest.get("lat"),
                "lng": latest.get("lng"),
                "accuracy": latest.get("accuracy"),
                "battery": latest.get("battery"),
                "last_seen": latest.get("timestamp"),
                "source": latest.get("source"),
                "city": latest.get("city", ""),
                "ping_count": len(pings)
            })
    return jsonify(devices)

@app.route("/api/history/<device_id>")
def get_history(device_id):
    db = load_db()
    return jsonify(db.get(device_id, []))

# ── DASHBOARD ────────────────────────────────────────
DASHBOARD = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>RecoverSoft — Live Tracking</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family: -apple-system, sans-serif; background:#0f1117; color:#fff; }
  
  header {
    padding: 16px 24px;
    background: #1a1d27;
    border-bottom: 1px solid #2a2d3a;
    display: flex;
    align-items: center;
    gap: 12px;
  }
  header h1 { font-size: 20px; font-weight: 700; }
  header span { color: #6c7280; font-size: 14px; }
  .dot { width:8px; height:8px; border-radius:50%; background:#22c55e; 
         animation: pulse 2s infinite; display:inline-block; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
  
  .layout { display: flex; height: calc(100vh - 57px); }
  
  #sidebar {
    width: 320px;
    background: #1a1d27;
    border-right: 1px solid #2a2d3a;
    overflow-y: auto;
    flex-shrink: 0;
  }
  
  .sidebar-title {
    padding: 16px;
    font-size: 12px;
    font-weight: 600;
    color: #6c7280;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    border-bottom: 1px solid #2a2d3a;
  }
  
  .device-card {
    padding: 16px;
    border-bottom: 1px solid #2a2d3a;
    cursor: pointer;
    transition: background 0.15s;
  }
  .device-card:hover { background: #22253a; }
  .device-card.active { background: #22253a; border-left: 3px solid #3b82f6; }
  
  .device-name { font-weight: 600; font-size: 14px; margin-bottom: 6px; }
  .device-meta { font-size: 12px; color: #6c7280; line-height: 1.6; }
  
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 99px;
    font-size: 11px;
    font-weight: 600;
    margin-left: 8px;
  }
  .badge-green { background: #14532d; color: #22c55e; }
  .badge-red   { background: #7f1d1d; color: #ef4444; }
  .badge-blue  { background: #1e3a5f; color: #60a5fa; }
  
  .battery-bar {
    height: 4px;
    background: #2a2d3a;
    border-radius: 2px;
    margin-top: 8px;
    overflow: hidden;
  }
  .battery-fill {
    height: 100%;
    border-radius: 2px;
    transition: width 0.3s;
  }
  
  #map { flex: 1; }
  
  .info-panel {
    position: absolute;
    bottom: 24px;
    right: 24px;
    background: #1a1d27;
    border: 1px solid #2a2d3a;
    border-radius: 12px;
    padding: 16px;
    min-width: 220px;
    z-index: 1000;
    display: none;
  }
  .info-panel h3 { font-size: 14px; margin-bottom: 8px; }
  .info-row { display:flex; justify-content:space-between; 
              font-size:12px; color:#6c7280; margin:4px 0; }
  .info-row span:last-child { color:#fff; }
  
  .no-devices {
    padding: 40px 20px;
    text-align: center;
    color: #6c7280;
    font-size: 14px;
  }

  .refresh-btn {
    margin: 12px 16px;
    padding: 8px 16px;
    background: #3b82f6;
    border: none;
    border-radius: 8px;
    color: white;
    font-size: 13px;
    cursor: pointer;
    width: calc(100% - 32px);
  }
  .refresh-btn:hover { background: #2563eb; }
</style>
</head>
<body>

<header>
  <div class="dot"></div>
  <h1>RecoverSoft</h1>
  <span>Live Device Tracking</span>
</header>

<div class="layout">
  <div id="sidebar">
    <div class="sidebar-title">Tracked Devices</div>
    <button class="refresh-btn" onclick="loadDevices()">↻ Refresh</button>
    <div id="device-list"><div class="no-devices">No devices yet</div></div>
  </div>
  <div id="map"></div>
</div>

<div class="info-panel" id="info-panel">
  <h3 id="info-name">Device</h3>
  <div class="info-row"><span>Coordinates</span><span id="info-coords">—</span></div>
  <div class="info-row"><span>Accuracy</span><span id="info-accuracy">—</span></div>
  <div class="info-row"><span>Battery</span><span id="info-battery">—</span></div>
  <div class="info-row"><span>Source</span><span id="info-source">—</span></div>
  <div class="info-row"><span>Last Seen</span><span id="info-lastseen">—</span></div>
  <div class="info-row"><span>City</span><span id="info-city">—</span></div>
</div>

<script>
const map = L.map('map').setView([-25.7479, 28.2293], 12); // Pretoria default

L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
  attribution: '© OpenStreetMap',
  className: 'dark-tiles'
}).addTo(map);

// Dark map style
document.head.insertAdjacentHTML('beforeend', `
  <style>.dark-tiles { filter: invert(100%) hue-rotate(180deg) brightness(95%) contrast(90%); }</style>
`);

let markers = {};
let selectedDevice = null;

function batteryColor(pct) {
  if (pct > 50) return '#22c55e';
  if (pct > 20) return '#f59e0b';
  return '#ef4444';
}

function timeAgo(ts) {
  if (!ts) return 'Unknown';
  const diff = Math.floor((Date.now() - new Date(ts)) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  return `${Math.floor(diff/3600)}h ago`;
}

function shortId(id) {
  return id.substring(0, 12) + '...';
}

async function loadDevices() {
  try {
    const res = await fetch('/api/devices');
    const devices = await res.json();
    renderSidebar(devices);
    renderMarkers(devices);
  } catch(e) {
    console.error('Failed to load devices', e);
  }
}

function renderSidebar(devices) {
  const list = document.getElementById('device-list');
  if (!devices.length) {
    list.innerHTML = '<div class="no-devices">No devices tracked yet.<br>Install tracker on a laptop to begin.</div>';
    return;
  }
  list.innerHTML = devices.map(d => `
    <div class="device-card ${selectedDevice === d.device_id ? 'active' : ''}"
         onclick="selectDevice('${d.device_id}', ${d.lat}, ${d.lng})">
      <div class="device-name">
        💻 ${shortId(d.device_id)}
        <span class="badge badge-green">Live</span>
      </div>
      <div class="device-meta">
        📍 ${d.lat?.toFixed(4)}, ${d.lng?.toFixed(4)}<br>
        🕐 ${timeAgo(d.last_seen)}<br>
        📡 ${d.source || 'unknown'} · ±${Math.round(d.accuracy || 0)}m
        ${d.city ? `· ${d.city}` : ''}
      </div>
      <div class="battery-bar">
        <div class="battery-fill" style="width:${d.battery||0}%;background:${batteryColor(d.battery||0)}"></div>
      </div>
      <div class="device-meta" style="margin-top:4px">🔋 ${d.battery ?? '?'}%</div>
    </div>
  `).join('');
}

function renderMarkers(devices) {
  devices.forEach(d => {
    if (!d.lat || !d.lng) return;
    
    const icon = L.divIcon({
      className: '',
      html: `<div style="
        width:16px;height:16px;border-radius:50%;
        background:#3b82f6;border:3px solid white;
        box-shadow:0 0 0 3px rgba(59,130,246,0.4);
      "></div>`,
      iconSize: [16, 16],
      iconAnchor: [8, 8]
    });
    
    if (markers[d.device_id]) {
      markers[d.device_id].setLatLng([d.lat, d.lng]);
    } else {
      markers[d.device_id] = L.marker([d.lat, d.lng], {icon})
        .addTo(map)
        .on('click', () => selectDevice(d.device_id, d.lat, d.lng));
    }
    
    // Accuracy circle
    if (markers[d.device_id + '_circle']) {
      map.removeLayer(markers[d.device_id + '_circle']);
    }
    markers[d.device_id + '_circle'] = L.circle([d.lat, d.lng], {
      radius: d.accuracy || 100,
      color: '#3b82f6',
      fillColor: '#3b82f6',
      fillOpacity: 0.1,
      weight: 1
    }).addTo(map);
  });
}

let historyLayer = null;
let historyDots = [];

function clearHistory() {
  if (historyLayer) { map.removeLayer(historyLayer); historyLayer = null; }
  historyDots.forEach(d => map.removeLayer(d));
  historyDots = [];
}

function drawHistory(pings) {
  clearHistory();
  if (pings.length < 2) return;

  // Draw trail line
  const coords = pings.map(p => [p.lat, p.lng]);
  historyLayer = L.polyline(coords, {
    color: '#f59e0b',
    weight: 2,
    opacity: 0.7,
    dashArray: '4 6'
  }).addTo(map);

  // Draw small dots for each ping
  pings.forEach((p, i) => {
    const isFirst = i === 0;
    const dot = L.circleMarker([p.lat, p.lng], {
      radius: isFirst ? 5 : 3,
      fillColor: isFirst ? '#ef4444' : '#f59e0b',
      color: 'white',
      weight: 1,
      fillOpacity: 0.8
    }).addTo(map);
    dot.bindTooltip(timeAgo(p.timestamp), {permanent: false});
    historyDots.push(dot);
  });

  // Fit map to show full trail
  map.fitBounds(historyLayer.getBounds(), {padding: [40, 40]});
}

function selectDevice(deviceId, lat, lng) {
  selectedDevice = deviceId;
  map.setView([lat, lng], 16);

  // Load history for this device
  fetch(`/api/history/${deviceId}`)
    .then(r => r.json())
    .then(pings => {
      drawHistory(pings);
    });

  fetch('/api/devices').then(r => r.json()).then(devices => {
    const d = devices.find(x => x.device_id === deviceId);
    if (!d) return;
    
    const panel = document.getElementById('info-panel');
    panel.style.display = 'block';
    document.getElementById('info-name').textContent = '💻 ' + shortId(d.device_id);
    document.getElementById('info-coords').textContent = `${d.lat?.toFixed(5)}, ${d.lng?.toFixed(5)}`;
    document.getElementById('info-accuracy').textContent = `±${Math.round(d.accuracy || 0)}m`;
    document.getElementById('info-battery').textContent = `${d.battery ?? '?'}%`;
    document.getElementById('info-source').textContent = d.source || '—';
    document.getElementById('info-lastseen').textContent = timeAgo(d.last_seen);
    document.getElementById('info-city').textContent = d.city || '—';
    
    renderSidebar(devices);
  });
}

// Load on start + auto refresh every 30s
loadDevices();
setInterval(loadDevices, 30000);
</script>
</body>
</html>
"""

@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD)

if __name__ == "__main__":
    print("RecoverSoft server running on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
