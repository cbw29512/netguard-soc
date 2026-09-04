#!/usr/bin/env python3
"""
NetGuard SOC Unified Dashboard Server v3.1
Comprehensive network monitoring with real-time updates
Now with WiFi band detection and enhanced marquee
"""
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
import subprocess
import sys
import json
import re
from pathlib import Path
from threading import Thread
import time
from datetime import datetime

sys.path.insert(0, '/opt/netguard/sensors/lib')
from safe_json import read_json_safe

app = Flask(__name__)
app.config['SECRET_KEY'] = 'netguard-soc-unified-v3.1'
socketio = SocketIO(app, cors_allowed_origins="*")

# Data file paths
TELEMETRY = Path("/var/lib/netguard/router_telemetry.json")
FINDINGS = Path("/var/lib/netguard/router_findings.json")
SYSLOG = Path("/var/lib/netguard/router_syslog_findings.json")
INVENTORY = Path("/var/lib/netguard/router_inventory.json")
HEALTH = Path("/var/lib/netguard/health.json")
AI_STATE = Path("/var/lib/netguard/ai_guard_state.json")
AI_RAG_STATE = Path("/var/lib/netguard/ai_rag_state.json")
AI_BRIEF = Path("/var/lib/netguard/router_ai_brief.json")
WIFI_ASSOC = Path("/var/lib/netguard/router_wifi_assoc.json")

# WiFi band mapping
WIFI_BANDS = {
    'wl0': '2.4GHz',
    'wl1': '5GHz', 
    'wl2': '6GHz'
}

# Services to monitor (name, display, has_timer)
SERVICES = [
    ("netguard-soc-web", "SOC Web", False),
    ("netguard-ai-guard", "AI Guard", False),
    ("netguard-ai", "AI Analyst", False),
    ("netguard-flow2influx", "Flow→Influx", False),
    ("netguard-enterprise", "Enterprise", False),
    ("netguard-router-telemetry", "Telemetry", True),
    ("netguard-router-anomaly", "Anomaly", True),
    ("netguard-router-syslog", "Syslog", True),
    ("netguard-router-ai", "Router AI", True),
    ("netguard-router-wifiassoc", "WiFi Assoc", True),
    ("netguard-wifi-scan", "WiFi Scan", True),
    ("netguard-health", "Health", True),
]

def get_service_status():
    """Get status of all netguard services (checks timer for timer-based services)"""
    services = []
    for svc_name, display_name, has_timer in SERVICES:
        try:
            if has_timer:
                # Check timer status instead of service
                result = subprocess.run(
                    ["systemctl", "is-active", f"{svc_name}.timer"],
                    capture_output=True, text=True, timeout=2
                )
            else:
                result = subprocess.run(
                    ["systemctl", "is-active", f"{svc_name}.service"],
                    capture_output=True, text=True, timeout=2
                )
            status = result.stdout.strip()
            is_ok = status in ("active", "activating")
        except:
            status = "unknown"
            is_ok = False
        services.append({
            "name": svc_name,
            "display": display_name,
            "status": status,
            "ok": is_ok
        })
    return services

def get_wifi_mac_to_band():
    """Build MAC -> WiFi band mapping from assoc data"""
    wifi_assoc = read_json_safe(WIFI_ASSOC, {})
    mac_to_band = {}
    
    if wifi_assoc.get('ok'):
        bases = wifi_assoc.get('wifi', {}).get('bases', {})
        for band_iface, info in bases.items():
            band_label = WIFI_BANDS.get(band_iface, band_iface)
            for mac in info.get('assoc_macs', []):
                mac_to_band[mac.lower()] = band_label
    
    return mac_to_band

def parse_connection_type(hostname, mac, mac_to_band):
    """Determine connection type from WiFi assoc data or hostname"""
    # First check real WiFi association data
    if mac in mac_to_band:
        return f"WiFi {mac_to_band[mac]}"
    
    # Fall back to hostname hints
    hostname_upper = (hostname or "").upper()
    if "LAN" in hostname_upper:
        return "Ethernet"
    elif "WIFI" in hostname_upper or "WIF" in hostname_upper:
        return "WiFi"  # Unknown band
    else:
        return "Unknown"

def format_lease_expiry(expiry_epoch):
    """Format lease expiry as human-readable countdown"""
    if not expiry_epoch:
        return "N/A"
    hours = expiry_epoch // 3600
    minutes = (expiry_epoch % 3600) // 60
    if hours > 0:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"

def format_first_seen(timestamp_str):
    """Format first seen timestamp"""
    if not timestamp_str:
        return None
    try:
        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        return dt.strftime("%b %d %H:%M")
    except:
        return None

@app.route('/')
def index():
    return render_template('soc_dashboard.html')

@app.route('/api/status')
def api_status():
    """System status overview"""
    telemetry = read_json_safe(TELEMETRY, {})
    findings = read_json_safe(FINDINGS, {})
    health = read_json_safe(HEALTH, {})
    ai_state = read_json_safe(AI_STATE, {})
    ai_rag_state = read_json_safe(AI_RAG_STATE, {})
    # NETGUARD_MARQUEE_RAG_MERGE_V1

    ai_brief = read_json_safe(AI_BRIEF, {})
    
    return jsonify({
        'telemetry_ok': telemetry.get('ok', False),
        'active_alerts': len(findings.get('alerts', [])),
        'health_status': health.get('status', 'unknown'),
        'ai_active': len(ai_state.get('thoughts', [])) > 0,
        'last_update': telemetry.get('generated_at', 'unknown'),
        'router_uptime': telemetry.get('router', {}).get('uptime', 'unknown'),
        'risk_score': ai_brief.get('risk_score', 0),
        'risk_level': ai_brief.get('risk_level', 'UNKNOWN')
    })

@app.route('/api/devices')
def api_devices():
    """Comprehensive device list with all available data"""
    telemetry = read_json_safe(TELEMETRY, {})
    findings = read_json_safe(FINDINGS, {})
    inventory = read_json_safe(INVENTORY, {})
    ai_state = read_json_safe(AI_STATE, {})
    
    if not telemetry.get('ok'):
        return jsonify({
            'devices': [],
            'count': 0,
            'error': telemetry.get('error', 'Telemetry unavailable')
        })
    
    # Get WiFi band mapping
    mac_to_band = get_wifi_mac_to_band()
    
    # Get device memory for first_seen
    device_memory = ai_state.get('device_memory', {})
    
    # Get data sources
    clients = telemetry.get('clients', {}) or {}
    leases = clients.get('dhcp_leases', []) or []
    arp_list = clients.get('arp', []) or []
    reservations = inventory.get('reservations', []) or []
    
    # Get findings details
    details = findings.get('details', {}) or {}
    unknown_devices = {d['mac'].lower(): d for d in details.get('unknown', []) or []}
    drift_devices = {d['mac'].lower(): d for d in details.get('reserved_drift', []) or []}
    
    # Build ARP lookup (online status)
    arp_map = {a.get('mac', '').lower(): a for a in arp_list}
    
    # Build reservation lookup
    res_map = {r.get('mac', '').lower(): r for r in reservations}
    
    devices = []
    for lease in leases:
        mac = (lease.get('mac', '') or '').lower()
        if not mac:
            continue
        
        ip = lease.get('ip', '')
        hostname = lease.get('hostname', '') or 'Unknown'
        expiry = lease.get('expiry_epoch', 0)
        
        # Check reservation
        reserved = res_map.get(mac)
        friendly_name = reserved.get('name', '') if reserved else ''
        
        # Check online status
        arp_entry = arp_map.get(mac)
        is_online = arp_entry is not None
        
        # Determine connection type from real WiFi data
        conn_type = parse_connection_type(hostname or friendly_name, mac, mac_to_band)
        
        # Get first seen
        mem_entry = device_memory.get(mac, {})
        first_seen = format_first_seen(mem_entry.get('first_seen'))
        
        # Check for alerts
        alerts = []
        if mac in unknown_devices:
            alerts.append({
                'type': 'unknown',
                'severity': 'warning',
                'message': 'Unknown device on network'
            })
        if mac in drift_devices:
            drift = drift_devices[mac]
            alerts.append({
                'type': 'drift',
                'severity': 'medium',
                'message': f"IP drift: expected {drift.get('want')}, got {drift.get('got')}"
            })
        
        # Check for private/randomized MAC
        is_private_mac = mac[1] in '26ae'
        if is_private_mac and mac not in res_map:
            alerts.append({
                'type': 'private_mac',
                'severity': 'low',
                'message': 'Randomized MAC address'
            })
        
        devices.append({
            'mac': mac,
            'ip': ip,
            'hostname': hostname,
            'friendly_name': friendly_name,
            'known': reserved is not None,
            'online': is_online,
            'conn_type': conn_type,
            'wifi_band': mac_to_band.get(mac),
            'lease_expiry': format_lease_expiry(expiry),
            'lease_seconds': expiry,
            'first_seen': first_seen,
            'alerts': alerts,
            'alert_count': len(alerts)
        })
    
    # Sort: alerts first, then online, then by IP
    def sort_key(d):
        ip_num = int(d['ip'].split('.')[-1]) if d['ip'] else 999
        return (not d["online"], ip_num)
    
    devices.sort(key=sort_key)
    
    return jsonify({
        'devices': devices,
        'count': len(devices),
        'summary': findings.get('summary', {})
    })

# NETGUARD_FLASK_AI_ENDPOINTS_V1
# Flask-safe AI endpoints (reads pre-generated JSON from disk)
from pathlib import Path as _NG_Path
import json as _NG_json
from flask import jsonify as _NG_jsonify

_NG_AI_STATE = "/var/lib/netguard/ai_rag_state.json"

def _ng_load_ai_state():
    p = _NG_Path(_NG_AI_STATE)
    if not p.exists():
        return {"ok": False, "generated_at": None, "model": None, "thoughts": []}
    try:
        data = _NG_json.loads(p.read_text(encoding="utf-8", errors="replace"))
        if not isinstance(data, dict):
            return {"ok": False, "error": "ai_state_not_object", "raw": data, "thoughts": []}
        data.setdefault("ok", True)
        data.setdefault("thoughts", [])
        return data
    except Exception as e:
        return {"ok": False, "error": str(e), "thoughts": []}

@app.route("/api/ai_thoughts")
def api_ai_thoughts():
    return _NG_jsonify(_ng_load_ai_state())





@app.route('/api/services')
def api_services():
    """Service status for footer"""
    return jsonify({
        'services': get_service_status(),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/router')
def api_router():
    """Router system stats"""
    telemetry = read_json_safe(TELEMETRY, {})
    router = telemetry.get('router', {})
    ai_brief = read_json_safe(AI_BRIEF, {})
    
    # Parse memory info
    meminfo = router.get('meminfo', '')
    mem_total = mem_free = 0
    for line in meminfo.split('\n'):
        if line.startswith('MemTotal:'):
            mem_total = int(re.search(r'(\d+)', line).group(1)) // 1024
        elif line.startswith('MemAvailable:'):
            mem_free = int(re.search(r'(\d+)', line).group(1)) // 1024
    
    # Parse load average
    loadavg = router.get('loadavg', '0 0 0').split()
    
    # Parse uptime
    uptime = router.get('uptime', '')
    uptime_match = re.search(r'up\s+([^,]+)', uptime)
    uptime_clean = uptime_match.group(1).strip() if uptime_match else uptime
    
    return jsonify({
        'host': telemetry.get('router_host', ''),
        'uname': router.get('uname', ''),
        'uptime': uptime_clean,
        'uptime_raw': router.get('uptime', ''),
        'load': loadavg[:3] if len(loadavg) >= 3 else ['0', '0', '0'],
        'mem_total_mb': mem_total,
        'mem_free_mb': mem_free,
        'mem_used_pct': round((1 - mem_free / mem_total) * 100, 1) if mem_total > 0 else 0,
        'risk_score': ai_brief.get('risk_score', 0),
        'risk_level': ai_brief.get('risk_level', 'UNKNOWN')
    })

@app.route('/api/wifi_bands')
def api_wifi_bands():
    """WiFi band status with association counts"""
    telemetry = read_json_safe(TELEMETRY, {})
    wifi_assoc = read_json_safe(WIFI_ASSOC, {})
    
    wifi = telemetry.get('wifi', {}).get('bands', {})
    assoc_bases = wifi_assoc.get('wifi', {}).get('bases', {}) if wifi_assoc.get('ok') else {}
    
    bands = []
    band_info = {
        'wl0': ('2.4 GHz', 'Ch 1'),
        'wl1': ('5 GHz', 'Ch 157'),
        'wl2': ('6 GHz', 'Ch 37')
    }
    
    for iface, info in wifi.items():
        label, channel = band_info.get(iface, (iface, 'Unknown'))
        status = info.get('status', '')
        
        # Parse channel utilization
        util_match = re.search(r'Channel Utilization: 0x[0-9a-f]+ \((\d+) %\)', status)
        utilization = int(util_match.group(1)) if util_match else 0
        
        # Parse noise floor
        noise_match = re.search(r'noise: (-?\d+) dBm', status)
        noise = int(noise_match.group(1)) if noise_match else -90
        
        # Get real association count from wifi_assoc
        assoc_info = assoc_bases.get(iface, {})
        assoc_count = assoc_info.get('assoc_count', 0)
        assoc_macs = assoc_info.get('assoc_macs', [])
        
        bands.append({
            'interface': iface,
            'label': label,
            'channel': channel,
            'assoc_count': assoc_count,
            'assoc_macs': assoc_macs,
            'utilization': utilization,
            'noise_dbm': noise
        })
    
    return jsonify({'bands': bands})

@app.route('/api/findings')
def api_findings():
    """Security findings and alerts"""
    findings = read_json_safe(FINDINGS, {})
    return jsonify(findings)

def broadcast_updates():
    """Push real-time updates to connected clients"""
    while True:
        time.sleep(2)
        try:
            with app.app_context():
                socketio.emit('update_devices', api_devices().get_json())
                socketio.emit('update_thoughts', {'thoughts': api_marquee().get_json().get('items', [])})
                socketio.emit('update_status', api_status().get_json())
                socketio.emit('update_services', api_services().get_json())
                socketio.emit('update_router', api_router().get_json())
                socketio.emit('update_wifi', api_wifi_bands().get_json())
        except Exception as e:
            print(f"Broadcast error: {e}")

@socketio.on('connect')
def handle_connect():
    print("Client connected to NetGuard SOC")
    emit('connected', {'status': 'Connected to Real Data Stream', 'version': '3.1'})



# NETGUARD_FORCE_MARQUEE_V1
from pathlib import Path as _NGM_Path
import json as _NGM_json
from flask import jsonify as _NGM_jsonify

_NGM_AI_STATE = "/var/lib/netguard/ai_rag_state.json"

def _ngm_load_ai_state():
    p = _NGM_Path(_NGM_AI_STATE)
    if not p.exists():
        return {"ok": False, "generated_at": None, "model": None, "thoughts": []}
    try:
        data = _NGM_json.loads(p.read_text(encoding="utf-8", errors="replace"))
        if not isinstance(data, dict):
            return {"ok": False, "error": "ai_state_not_object", "raw": data, "thoughts": []}
        data.setdefault("ok", True)
        data.setdefault("thoughts", [])
        return data
    except Exception as e:
        return {"ok": False, "error": str(e), "thoughts": []}

@app.route("/api/marquee")
def api_marquee():
    data = _ngm_load_ai_state()
    thoughts = data.get("thoughts") or []
    parts = []
    for t in thoughts:
        if isinstance(t, dict):
            parts.append(str(t.get("thought","")).strip())
        else:
            parts.append(str(t).strip())
    text = "  •  ".join([p for p in parts if p])[:2000]
    return _NGM_jsonify({
        "ok": data.get("ok", False),
        "generated_at": data.get("generated_at"),
        "text": text,
        "items": thoughts
    })





# NETGUARD_ALERTS_OVERRIDE_PATH_LOCK_V4
# Single source of truth for alert overrides persistence.
import os as _NG_os
_NG_OVERRIDES_PATH = _NG_os.getenv("NG_ALERTS_OVERRIDES_PATH", "/var/lib/netguard/alerts_overrides.json")


# NETGUARD_ALERTS_API_V1
import os, json, hashlib, time
from datetime import datetime

try:
    from flask import request as _NG_request, jsonify as _NG_jsonify
except Exception:
    _NG_request = None
    _NG_jsonify = None

_ALERTS_PATH = "/var/lib/netguard/alerts.json"
_AI_RAG_PATH = "/var/lib/netguard/ai_rag_state.json"
_AI_GUARD_PATH = "/var/lib/netguard/ai_guard_state.json"

def _ng_id(*parts: str) -> str:
    raw = "||".join([p for p in parts if p is not None])
    return hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()[:16]

def _ng_read_json(path: str):
    try:
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def _ng_atomic_write(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)

def _ng_load_store() -> dict:
    store = _ng_read_json(_ALERTS_PATH)
    if not isinstance(store, dict):
        store = {"schema": 1, "alerts": [], "tombstones": {}}
    store.setdefault("schema", 1)
    store.setdefault("alerts", [])
    store.setdefault("tombstones", {})
    # normalize list
    if not isinstance(store["alerts"], list):
        store["alerts"] = []
    if not isinstance(store["tombstones"], dict):
        store["tombstones"] = {}
    return store

def _ng_save_store(store: dict) -> None:
    _ng_atomic_write(_ALERTS_PATH, store)

def _ng_synthesize_alerts() -> list:
    """Create alerts from AI state files (guard + rag)."""
    out = []

    rag = _ng_read_json(_AI_RAG_PATH) or {}
    for t in (rag.get("thoughts") or []):
        try:
            lvl = (t.get("level") or "info").lower()
            txt = (t.get("thought") or "").strip()
            ts = (t.get("timestamp") or rag.get("generated_at") or _ng_now_iso())
            if not txt:
                continue
            # Only surface actionable levels as alerts
            if lvl not in ("warning","error","critical","suggestion","info"):
                continue
            aid = _ng_id("rag", lvl, txt)
            out.append({
                "id": aid,
                "source": "AI_RAG",
                "level": lvl,
                "title": txt[:72] + ("…" if len(txt) > 72 else ""),
                "detail": txt,
                "timestamp": ts,
                "status": "open",
                "requires_admin": lvl in ("warning", "error", "critical"),
                "ai_detail": None,
                "approved_at": None,
                "dismissed_at": None,
            })
        except Exception:
            continue

    guard = _ng_read_json(_AI_GUARD_PATH) or {}
    # If guard already has structured alerts, merge them
    for a in (guard.get("alerts") or []):
        try:
            lvl = (a.get("level") or "warning").lower()
            txt = (a.get("message") or a.get("detail") or "").strip()
            ts = (a.get("timestamp") or guard.get("generated_at") or _ng_now_iso())
            if not txt:
                continue
            aid = a.get("id") or _ng_id("guard", lvl, txt)
            out.append({
                "id": aid,
                "source": "AI_GUARD",
                "level": lvl,
                "title": (a.get("title") or txt[:72] + ("…" if len(txt) > 72 else "")),
                "detail": (a.get("detail") or txt),
                "timestamp": ts,
                "status": "open",
                "requires_admin": True,
                "ai_detail": None,
                "approved_at": None,
                "dismissed_at": None,
            })
        except Exception:
            continue

    # sort newest first if timestamps parse poorly, it's ok
    return out

def _ng_merge_store_with_synth(store: dict, synth: list) -> dict:
    tomb = store.get("tombstones", {}) or {}
    existing = {a.get("id"): a for a in (store.get("alerts") or []) if isinstance(a, dict) and a.get("id")}
    merged = existing.copy()

    for a in synth:
        aid = a["id"]
        if aid in tomb:
            continue  # user deleted it; don't resurrect
        if aid in merged:
            # keep user state; refresh text fields if changed
            keep = merged[aid]
            for k in ("title", "detail", "timestamp", "level", "source", "requires_admin"):
                if a.get(k) is not None:
                    keep[k] = a[k]
            merged[aid] = keep
        else:
            merged[aid] = a

    # Filter out hard-deleted items (tombstones already block synth)
    store["alerts"] = list(merged.values())
    return store

def _ng_public_alerts(store: dict) -> list:
    # return everything except tombstoned ids (shouldn't be present anyway)
    tomb = store.get("tombstones", {}) or {}
    out = []
    for a in (store.get("alerts") or []):
        if not isinstance(a, dict): 
            continue
        aid = a.get("id")
        if not aid or aid in tomb:
            continue
        out.append(a)
    # stable ordering: newest first by timestamp string
    out.sort(key=lambda x: (x.get("timestamp") or ""), reverse=True)
    return out


# NETGUARD_ALERTS_OVERRIDES_HELPERS_V2

# NETGUARD_ALERTS_FINGERPRINT_HELPERS_V3
def _ng_alert_fingerprint_fields(source=None, level=None, title=None, detail=None) -> str:
    """Stable key across regenerations. Returns like: fp:abcd1234..."""
    try:
        import hashlib
        def norm(x):
            return " ".join(str(x or "").strip().lower().split())
        blob = "|".join([norm(source), norm(level), norm(title), norm(detail)])
        h = hashlib.sha256(blob.encode("utf-8", errors="ignore")).hexdigest()[:16]
        return f"fp:{h}"
    except Exception:
        return ""

def _ng_alert_fp(alert: dict) -> str:
    try:
        return _ng_alert_fingerprint_fields(
            alert.get("source"), alert.get("level"), alert.get("title"), alert.get("detail")
        )
    except Exception:
        return ""
_NG_ALERTS_OVERRIDES_PATH = "/var/lib/netguard/alerts_overrides.json"

def _ng_now_iso():
    try:
        from datetime import datetime
        return datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")
    except Exception:
        import time
        return str(int(time.time()))

def _ng_load_overrides():
    try:
        import json, os
        p = _NG_ALERTS_OVERRIDES_PATH
        if not os.path.exists(p):
            return {}
        with open(p, "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}

def _ng_save_overrides(d: dict):
    try:
        import json, os
        p = _NG_ALERTS_OVERRIDES_PATH
        os.makedirs(os.path.dirname(p), exist_ok=True)
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
        try:
            os.chmod(p, 0o644)
        except Exception:
            pass
        return True
    except Exception as e:
        try:
            print("[netguard] overrides save failed:", repr(e))
        except Exception:
            pass
        return False

@app.route("/api/alerts", methods=["GET"])
def ng_api_alerts():
    store = _ng_load_store()
    store = _ng_merge_store_with_synth(store, _ng_synthesize_alerts())
    _ng_save_store(store)

    alerts = _ng_public_alerts(store)
    actionable_levels = {"warning","error","critical","suggestion"}
    open_count = sum(1 for a in alerts if (a.get("status") or "open") == "open" and (a.get("level") or "").lower() in actionable_levels)
    payload = {"timestamp": _ng_now_iso(), "open_count": open_count, "alerts": alerts}
    # NETGUARD_ALERTS_APPLY_OVERRIDES_V2
    try:
        _ovr = _ng_load_overrides()
        if isinstance(_ovr, dict) and _ovr:
            _new = []
            for a in alerts:
                aid = (a.get("id") or "")
                fp = _ng_alert_fp(a)
                ov = _ovr.get(aid) or (_ovr.get(fp) if fp else None)
                if isinstance(ov, dict):
                    if (ov.get("status") or "").lower() == "deleted":
                        continue
                    # apply overrides (status/dismissed_at/approved_at/ai_detail/requires_admin)
                    for k, v in ov.items():
                        if v is not None:
                            a[k] = v
                _new.append(a)
            alerts = _new
        # recompute open_count (actionable-only)
        _actionable = {"warning","error","critical","suggestion"}
        open_count = sum(
            1 for a in alerts
            if (a.get("status") or "open") == "open"
            and (str(a.get("level") or "").lower() in _actionable)
        )
    except Exception:
        pass

    return _NG_jsonify(payload) if _NG_jsonify else payload

def _ng_find_alert(store: dict, alert_id: str):
    for a in store.get("alerts", []) or []:
        if isinstance(a, dict) and a.get("id") == alert_id:
            return a
    return None

@app.route("/api/alerts/<alert_id>/dismiss", methods=["POST"])
def ng_api_alert_dismiss(alert_id):
    store = _ng_load_store()
    store = _ng_merge_store_with_synth(store, _ng_synthesize_alerts())
    a = _ng_find_alert(store, alert_id)
    if not a:
        return ("Not found", 404)
    a["status"] = "dismissed"
    a["dismissed_at"] = _ng_now_iso()
    _ng_save_store(store)
    return _NG_jsonify({"ok": True, "id": alert_id, "status": a["status"]}) if _NG_jsonify else {"ok": True}

@app.route("/api/alerts/<alert_id>/approve", methods=["POST"])
def ng_api_alert_approve(alert_id):
    store = _ng_load_store()
    store = _ng_merge_store_with_synth(store, _ng_synthesize_alerts())
    a = _ng_find_alert(store, alert_id)
    if not a:
        return ("Not found", 404)
    a["status"] = "approved"
    a["approved_at"] = _ng_now_iso()
    a["requires_admin"] = False
    _ng_save_store(store)
    return _NG_jsonify({"ok": True, "id": alert_id, "status": a["status"]}) if _NG_jsonify else {"ok": True}

@app.route("/api/alerts/<alert_id>/reset", methods=["POST"])
def ng_api_alert_reset(alert_id):
    store = _ng_load_store()
    store = _ng_merge_store_with_synth(store, _ng_synthesize_alerts())
    a = _ng_find_alert(store, alert_id)
    if not a:
        return ("Not found", 404)
    a["status"] = "open"
    a["ai_detail"] = None
    a["approved_at"] = None
    a["dismissed_at"] = None
    _ng_save_store(store)
    return _NG_jsonify({"ok": True, "id": alert_id, "status": a["status"]}) if _NG_jsonify else {"ok": True}

@app.route("/api/alerts/<alert_id>/delete", methods=["POST"])
def ng_api_alert_delete(alert_id):
    store = _ng_load_store()
    store = _ng_merge_store_with_synth(store, _ng_synthesize_alerts())
    # tombstone it so synth doesn't resurrect
    store.setdefault("tombstones", {})
    store["tombstones"][alert_id] = _ng_now_iso()
    # remove from list
    store["alerts"] = [a for a in (store.get("alerts") or []) if not (isinstance(a, dict) and a.get("id") == alert_id)]
    _ng_save_store(store)
    return _NG_jsonify({"ok": True, "id": alert_id, "deleted": True}) if _NG_jsonify else {"ok": True}

@app.route("/api/alerts/<alert_id>/ai_expand", methods=["POST"])
def ng_api_alert_ai_expand(alert_id):
    store = _ng_load_store()
    store = _ng_merge_store_with_synth(store, _ng_synthesize_alerts())
    a = _ng_find_alert(store, alert_id)
    if not a:
        return ("Not found", 404)

    # fast + safe "AI expand" (no heavy calls). You can later swap this for an Ollama call.
    lvl = (a.get("level") or "warning").upper()
    src = a.get("source") or "UNKNOWN"
    detail = (a.get("detail") or "").strip()

    guidance = []
    if "dhcp" in detail.lower():
        guidance += [
            "Check DHCP leases for unknown MACs and confirm reservations.",
            "Reduce lease time temporarily if you are hunting rogue devices.",
            "Correlate with Wi-Fi associations + switch port activity."
        ]
    if "mem" in detail.lower() or "memory" in detail.lower():
        guidance += [
            "Identify top consumers: VPN, IDS, logging bursts, or Wi-Fi scanning spikes.",
            "Consider lowering telemetry cadence during peak load.",
            "Watch for repeated restarts / crashes causing cache churn."
        ]
    if not guidance:
        guidance = [
            "Cross-check router telemetry + recent traffic anomalies for correlation.",
            "If this repeats, promote to an admin-required policy decision (block/allow).",
            "If unclear, request a deeper AI analysis with a larger context window."
        ]

    a["ai_detail"] = {
        "generated_at": _ng_now_iso(),
        "summary": f"[{src}/{lvl}] Expanded context + next actions",
        "recommended_actions": guidance,
    }
    _ng_save_store(store)
    return _NG_jsonify({"ok": True, "id": alert_id, "ai_detail": a["ai_detail"]}) if _NG_jsonify else {"ok": True}



# NETGUARD_ALERTS_ACTION_ENDPOINTS_V2
@app.route('/api/alerts/<alert_id>/dismiss', methods=['POST'])
def api_alert_dismiss(alert_id):
    o = _ng_load_overrides()
    # fp-aware overrides: UI sends {source,level,title,detail}
    try:
        payload = _NG_request.get_json(silent=True) if _NG_request else None
    except Exception:
        payload = None
    payload = payload or {}
    fp = payload.get('fingerprint') or _ng_alert_fingerprint_fields(payload.get('source'), payload.get('level'), payload.get('title'), payload.get('detail'))
    o[str(alert_id)] = {
        "status": "dismissed",
        "dismissed_at": _ng_now_iso(),
    }
    if fp:
        o[fp] = o.get(str(alert_id), {}).copy() if isinstance(o.get(str(alert_id)), dict) else o[str(alert_id)]
    if fp:
        o[fp] = o.get(str(alert_id), {}).copy() if isinstance(o.get(str(alert_id)), dict) else o[str(alert_id)]
    _ng_save_overrides(o)
    return _NG_jsonify({"ok": True, "id": alert_id, "status": "dismissed"})

@app.route('/api/alerts/<alert_id>/delete', methods=['POST'])
def api_alert_delete(alert_id):
    o = _ng_load_overrides()
    # fp-aware overrides: UI sends {source,level,title,detail}
    try:
        payload = _NG_request.get_json(silent=True) if _NG_request else None
    except Exception:
        payload = None
    payload = payload or {}
    fp = payload.get('fingerprint') or _ng_alert_fingerprint_fields(payload.get('source'), payload.get('level'), payload.get('title'), payload.get('detail'))
    o[str(alert_id)] = {
        "status": "deleted",
        "dismissed_at": _ng_now_iso(),
    }
    _ng_save_overrides(o)
    return _NG_jsonify({"ok": True, "id": alert_id, "status": "deleted"})

@app.route('/api/alerts/<alert_id>/approve', methods=['POST'])
def api_alert_approve(alert_id):
    o = _ng_load_overrides()
    # fp-aware overrides: UI sends {source,level,title,detail}
    try:
        payload = _NG_request.get_json(silent=True) if _NG_request else None
    except Exception:
        payload = None
    payload = payload or {}
    fp = payload.get('fingerprint') or _ng_alert_fingerprint_fields(payload.get('source'), payload.get('level'), payload.get('title'), payload.get('detail'))
    cur = o.get(str(alert_id), {}) if isinstance(o.get(str(alert_id)), dict) else {}
    cur.update({
        "status": "approved",
        "approved_at": _ng_now_iso(),
        "requires_admin": False,
    })
    o[str(alert_id)] = cur
    if fp:
        o[fp] = cur
    _ng_save_overrides(o)
    return _NG_jsonify({"ok": True, "id": alert_id, "status": "approved"})

@app.route('/api/alerts/<alert_id>/reset', methods=['POST'])
def api_alert_reset(alert_id):
    o = _ng_load_overrides()
    # fp-aware overrides: UI sends {source,level,title,detail}
    try:
        payload = _NG_request.get_json(silent=True) if _NG_request else None
    except Exception:
        payload = None
    payload = payload or {}
    fp = payload.get('fingerprint') or _ng_alert_fingerprint_fields(payload.get('source'), payload.get('level'), payload.get('title'), payload.get('detail'))
    o.pop(str(alert_id), None)
    if fp:
        o.pop(fp, None)
    _ng_save_overrides(o)
    return _NG_jsonify({"ok": True, "id": alert_id, "status": "open"})

@app.route('/api/alerts/<alert_id>/ask_ai', methods=['POST'])
def api_alert_ask_ai(alert_id):
    # expects JSON: {title, detail, level, source, question(optional)}
    try:
        payload = _NG_request.get_json(silent=True) if _NG_request else None
    except Exception:
        payload = None
    payload = payload or {}
    title = (payload.get("title") or "").strip()
    detail = (payload.get("detail") or "").strip()
    level = (payload.get("level") or "").strip()
    source = (payload.get("source") or "").strip()
    question = (payload.get("question") or "Give more context, likely causes, and next checks. Provide a short manual action plan.").strip()

    prompt = (
        "You are NetGuard SOC assistant. Provide concise actionable analysis.\n"
        f"ALERT_ID: {alert_id}\n"
        f"LEVEL: {level}\n"
        f"SOURCE: {source}\n"
        f"TITLE: {title}\n"
        f"DETAIL: {detail}\n"
        f"USER_QUESTION: {question}\n"
        "Return:\n"
        "1) What it likely means\n2) Likely causes\n3) What to check next (specific)\n4) Suggested manual action\n"
    )

    ai_text = None
    # Try local Ollama (if present)
    try:
        import subprocess, shlex
        model = payload.get("model") or "llama3.2:latest"
        # Keep it safe/fast: single run, small timeout
        proc = subprocess.run(
            ["ollama", "run", str(model)],
            input=prompt.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=25,
        )
        if proc.returncode == 0:
            ai_text = proc.stdout.decode("utf-8", errors="replace").strip()
        else:
            ai_text = ("Ollama error: " + proc.stderr.decode("utf-8", errors="replace").strip())[:2000]
    except Exception as e:
        ai_text = f"Ollama not available or failed: {e}"

    o = _ng_load_overrides()
    cur = o.get(str(alert_id), {}) if isinstance(o.get(str(alert_id)), dict) else {}
    cur.update({
        "ai_detail": ai_text,
    })
    o[str(alert_id)] = cur
    _ng_save_overrides(o)
    return _NG_jsonify({"ok": True, "id": alert_id, "ai_detail": ai_text})

# NETGUARD_ALERTS_ACTION_UNIFIED_V6
# Unified action endpoint that ALWAYS persists to alerts_overrides.json (fp-sticky).
try:
    from flask import request as _NG_request, jsonify as _NG_jsonify
except Exception:
    _NG_request = None
    _NG_jsonify = None

def _ng_v6_now_iso() -> str:
    try:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()
    except Exception:
        return ""

def _ng_v6_fp(source=None, level=None, title=None, detail=None) -> str:
    try:
        import hashlib
        raw = f"{source or ''}\n{(level or '').lower()}\n{title or ''}\n{detail or ''}".encode("utf-8","ignore")
        return "fp:" + hashlib.sha1(raw).hexdigest()[:16]
    except Exception:
        return ""

def _ng_v6_load() -> dict:
    try:
        return _ng_load_overrides()  # existing helper from earlier patches
    except Exception:
        try:
            import json
            from pathlib import Path
            pp = Path("/var/lib/netguard/alerts_overrides.json")
            return json.loads(pp.read_text(encoding="utf-8")) if pp.exists() else {}
        except Exception:
            return {}

def _ng_v6_save(d: dict) -> None:
    try:
        _ng_save_overrides(d)  # V5 atomic saver already appended
        return
    except Exception:
        pass
    # fallback atomic
    try:
        import os, json
        path = "/var/lib/netguard/alerts_overrides.json"
        tmp  = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception as e:
        try:
            print("[netguard] V6 overrides save failed:", repr(e))
        except Exception:
            pass

def _ng_v6_key(aid: str, payload: dict) -> str:
    # Prefer fp if we have enough fields; fallback to id.
    src   = payload.get("source") or payload.get("alert",{}).get("source")
    lvl   = payload.get("level")  or payload.get("alert",{}).get("level")
    title = payload.get("title")  or payload.get("alert",{}).get("title")
    det   = payload.get("detail") or payload.get("alert",{}).get("detail")
    fp = _ng_v6_fp(src, lvl, title, det) if (src or title or det) else ""
    return fp if fp else (aid or "")

@app.route("/api/alerts_action", methods=["POST"])
def ng_alerts_action_v6():
    if _NG_request is None or _NG_jsonify is None:
        return ("alerts_action unavailable", 500)

    payload = _NG_request.get_json(silent=True) or {}
    aid = (payload.get("id") or "").strip()
    action = (payload.get("action") or "").strip().lower()

    key = _ng_v6_key(aid, payload)
    if not key:
        return _NG_jsonify({"ok": False, "error": "missing id/fingerprint"}), 400

    o = _ng_v6_load()
    rec = o.get(key, {})
    now = _ng_v6_now_iso()

    # Apply action
    if action in ("dismiss","dismissed"):
        rec["status"] = "dismissed"
        rec["dismissed_at"] = now
    elif action in ("approve","approved","admin_approve"):
        rec["status"] = "approved"
        rec["approved_at"] = now
        # If approved, it no longer requires admin.
        rec["requires_admin"] = False
    elif action in ("reset","reopen","open"):
        # Clear overrides but keep record minimal (so it stops sticking)
        rec = {"status": "open", "dismissed_at": None, "approved_at": None, "ai_detail": None}
    elif action in ("ai_detail","more","explain","info"):
        # “Ask AI for more info” (stub for now, but interactive)
        existing = rec.get("ai_detail")
        rec["ai_detail"] = existing or f"AI follow-up requested at {now}. (stub: connect Ollama enrichment next)"
    else:
        return _NG_jsonify({"ok": False, "error": f"unknown action: {action}"}), 400

    o[key] = rec
    _ng_v6_save(o)

    return _NG_jsonify({
        "ok": True,
        "id": aid,
        "key": key,
        "action": action,
        "status": rec.get("status","open")
    })

# NETGUARD_DEVICE_ENDPOINTS_V1
try:
    from flask import request as _NG_req, jsonify as _NG_json
except Exception:
    _NG_req = None
    _NG_json = None

@app.route('/api/device_flows')
def ng_device_flows():
    if _NG_req is None or _NG_json is None:
        return ("unavailable", 500)
    
    ip = _NG_req.args.get('ip','').strip()
    mac = _NG_req.args.get('mac','').strip()
    limit = int(_NG_req.args.get('limit', 100))
    
    # Query InfluxDB for flows matching this device
    flows = []
    try:
        from influxdb_client import InfluxDBClient
        client = InfluxDBClient(url="http://localhost:8086", token="netguard-token", org="netguard")
        
        # Build query (avoid f-string issues with Flux syntax)
        query_parts = [
            'from(bucket: "netguard")',
            '  |> range(start: -24h)',
            '  |> filter(fn: (r) => r["_measurement"] == "flow")',
            '  |> filter(fn: (r) => r["src_ip"] == "' + ip + '" or r["dst_ip"] == "' + ip + '")',
            '  |> limit(n: ' + str(limit) + ')',
            '  |> sort(columns: ["_time"], desc: true)'
        ]
        query = '\n'.join(query_parts)
        
        tables = client.query_api().query(query, org="netguard")
        for table in tables:
            for rec in table.records:
                flows.append({
                    "timestamp": rec.get_time().isoformat() if rec.get_time() else "",
                    "src_ip": rec.values.get("src_ip",""),
                    "dst_ip": rec.values.get("dst_ip",""),
                    "dst_port": rec.values.get("dst_port",""),
                    "protocol": rec.values.get("protocol",""),
                    "bytes": rec.values.get("bytes",0),
                    "packets": rec.values.get("packets",0)
                })
        client.close()
    except Exception as e:
        return _NG_json({"ok":False, "error":str(e), "flows":[]})
    
    return _NG_json({"ok":True, "flows":flows})

@app.route('/api/device_action', methods=['POST'])
def ng_device_action():
    if _NG_req is None or _NG_json is None:
        return ("unavailable", 500)
    
    payload = _NG_req.get_json(silent=True) or {}
    action = payload.get('action','').strip()
    ip = payload.get('ip','').strip()
    mac = payload.get('mac','').strip()
    hostname = payload.get('hostname','').strip()
    
    # Stub implementations - integrate with your router/firewall
    result = {"ok":True, "action":action, "message":""}
    
    if action == 'label':
        result["message"] = f"Label device: prompt user for new name (implement label DB next)"
    elif action == 'cap':
        result["message"] = f"Bandwidth cap: integrate with QoS API (router-specific)"
    elif action == 'quarantine':
        result["message"] = f"Quarantine {ip}: move to isolated VLAN (requires router support)"
    elif action == 'block':
        result["message"] = f"Block {mac}: add to firewall blocklist (implement next)"
    elif action == 'scan':
        result["message"] = f"Port scan {ip}: launching nmap scan (background job)"
    elif action == 'history':
        result["message"] = f"Historical data for {ip}: query InfluxDB for 7-day graph"
    else:
        result["ok"] = False
        result["message"] = f"Unknown action: {action}"
    
    return _NG_json(result)






if __name__ == '__main__':
    Thread(target=broadcast_updates, daemon=True).start()
    socketio.run(app, host='0.0.0.0', port=8055, debug=False, allow_unsafe_werkzeug=True)
