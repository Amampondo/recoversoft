"""
RecoverSoft Windows Tracker
- Runs hidden in background
- Auto starts with Windows
- Reserves 10% battery
- Pings server every 30 seconds
"""

import os
import sys
import time
import json
import uuid
import socket
import requests
import threading
import winreg
import subprocess
from datetime import datetime, UTC
from pathlib import Path

# ── CONFIG ───────────────────────────────────────────
SERVER_URL      = "https://skewed-smolder-promotion.ngrok-free.dev/api/ping"
PING_INTERVAL   = 30   # seconds
BATTERY_RESERVE = 10   # percent hidden from user
APP_NAME        = "RecoverSoft"
APP_PATH        = Path(sys.executable if getattr(sys, 'frozen', False) 
                       else __file__).resolve()

# ── DEVICE ID ────────────────────────────────────────
def get_device_id():
    """Persistent device ID stored in AppData."""
    id_file = Path(os.environ['APPDATA']) / 'RecoverSoft' / 'device.id'
    id_file.parent.mkdir(parents=True, exist_ok=True)
    if id_file.exists():
        return id_file.read_text().strip()
    device_id = str(uuid.uuid4())
    id_file.write_text(device_id)
    return device_id

# ── STARTUP ───────────────────────────────────────────
def add_to_startup():
    """Add app to Windows startup via registry."""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, str(APP_PATH))
        winreg.CloseKey(key)
    except Exception as e:
        log(f"Startup registration failed: {e}")

def remove_from_startup():
    """Remove from startup (for uninstall)."""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE
        )
        winreg.DeleteValue(key, APP_NAME)
        winreg.CloseKey(key)
    except:
        pass

# ── BATTERY ───────────────────────────────────────────
def get_battery():
    """Get real battery percentage via WMI."""
    try:
        import wmi
        w = wmi.WMI()
        battery = w.Win32_Battery()[0]
        return battery.EstimatedChargeRemaining
    except:
        try:
            # Fallback via psutil
            import psutil
            b = psutil.sensors_battery()
            return int(b.percent) if b else None
        except:
            return None

def get_reported_battery(real):
    """What user sees = real - reserve."""
    if real is None:
        return None
    return max(0, real - BATTERY_RESERVE)

def enforce_battery_reserve():
    """Hibernate OS when real battery hits reserve."""
    real = get_battery()
    if real is not None and real <= BATTERY_RESERVE:
        log(f"Battery at {real}% — hibernating OS, tracker continues")
        # Hibernate keeps tracker running in background
        subprocess.run(["shutdown", "/h"], shell=True)
        return True
    return False

def override_battery_display(real):
    """
    Override Windows battery display via powercfg.
    Sets low battery warning to trigger at reserve+10%
    so user thinks they're lower than they are.
    """
    try:
        # Set low battery level higher so user suspends earlier
        threshold = BATTERY_RESERVE + 10
        subprocess.run(
            f'powercfg /setdcvalueindex SCHEME_CURRENT SUB_BATTERY BATACTIONCRIT 1',
            shell=True, capture_output=True
        )
        subprocess.run(
            f'powercfg /setdcvalueindex SCHEME_CURRENT SUB_BATTERY BATLEVELLOW {threshold}',
            shell=True, capture_output=True
        )
    except:
        pass

# ── LOCATION ─────────────────────────────────────────
def get_wifi_networks():
    """Scan WiFi networks via netsh."""
    try:
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
            capture_output=True, text=True, timeout=10
        )
        networks = []
        lines = result.stdout.split('\n')
        bssid = None
        signal = None
        for line in lines:
            line = line.strip()
            if 'BSSID' in line and ':' in line:
                bssid = line.split(':', 1)[1].strip()
            if 'Signal' in line and ':' in line:
                try:
                    signal = int(line.split(':')[1].strip().replace('%', ''))
                    signal = (signal / 2) - 100  # convert to dBm
                except:
                    signal = -70
            if bssid and signal:
                networks.append({
                    "macAddress": bssid,
                    "signalStrength": int(signal)
                })
                bssid = None
                signal = None
        return networks[:10]
    except:
        return []

def get_location_from_wifi(networks):
    """Mozilla Location Service — free, no API key."""
    if not networks:
        return None
    try:
        resp = requests.post(
            "https://location.services.mozilla.com/v1/geolocate?key=test",
            json={"wifiAccessPoints": networks},
            timeout=10
        )
        data = resp.json()
        if "location" in data:
            return {
                "lat": data["location"]["lat"],
                "lng": data["location"]["lng"],
                "accuracy": data.get("accuracy", 999),
                "source": "wifi"
            }
    except:
        pass
    return None

def get_location_from_ip():
    """IP fallback — free."""
    try:
        resp = requests.get("http://ip-api.com/json/", timeout=10)
        data = resp.json()
        return {
            "lat": data.get("lat", 0),
            "lng": data.get("lon", 0),
            "accuracy": 5000,
            "source": "ip",
            "city": data.get("city", "")
        }
    except:
        return None

def get_location():
    """Best available location."""
    wifi = get_wifi_networks()
    loc = get_location_from_wifi(wifi)
    if loc:
        return loc
    return get_location_from_ip() or {
        "lat": 0, "lng": 0, "accuracy": 99999, "source": "unknown"
    }

# ── LOGGING ───────────────────────────────────────────
log_file = Path(os.environ['APPDATA']) / 'RecoverSoft' / 'tracker.log'

def log(msg):
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with open(log_file, 'a') as f:
        f.write(f"{datetime.now(UTC).isoformat()} {msg}\n")

# ── PING ──────────────────────────────────────────────
def ping_server(device_id, location, battery):
    payload = {
        "device_id":  device_id,
        "timestamp":  datetime.now(UTC).isoformat(),
        "lat":        location.get("lat"),
        "lng":        location.get("lng"),
        "accuracy":   location.get("accuracy"),
        "source":     location.get("source"),
        "battery":    battery,
        "city":       location.get("city", ""),
        "hostname":   socket.gethostname(),
    }
    try:
        r = requests.post(SERVER_URL, json=payload, timeout=10)
        log(f"Pinged: {payload['lat']},{payload['lng']} battery={battery}%")
        return r.status_code == 200
    except Exception as e:
        log(f"Ping failed: {e}")
        cache_ping(payload)
        return False

def cache_ping(payload):
    cache = Path(os.environ['APPDATA']) / 'RecoverSoft' / 'pending.json'
    try:
        pings = json.loads(cache.read_text()) if cache.exists() else []
        pings.append(payload)
        cache.write_text(json.dumps(pings[-100:]))
    except:
        pass

def upload_cached():
    cache = Path(os.environ['APPDATA']) / 'RecoverSoft' / 'pending.json'
    if not cache.exists():
        return
    try:
        pings = json.loads(cache.read_text())
        if not pings:
            return
        r = requests.post(
            SERVER_URL.replace('/ping', '/batch'),
            json={"pings": pings}, timeout=15
        )
        if r.status_code == 200:
            cache.unlink()
            log(f"Uploaded {len(pings)} cached pings")
    except:
        pass

# ── MAIN ──────────────────────────────────────────────
def main():
    # Register startup
    add_to_startup()

    device_id = get_device_id()
    log(f"RecoverSoft started. Device: {device_id}")

    while True:
        try:
            # Battery
            real = get_battery()
            reported = get_reported_battery(real)
            enforce_battery_reserve()
            if real:
                override_battery_display(real)

            # Location
            location = get_location()

            # Upload cached + ping
            upload_cached()
            ping_server(device_id, location, reported)

        except Exception as e:
            log(f"Error: {e}")

        time.sleep(PING_INTERVAL)

if __name__ == "__main__":
    main()
