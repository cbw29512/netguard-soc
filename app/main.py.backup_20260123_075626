from fastapi import FastAPI, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import json, pathlib, requests, sys

# Add lib path for new functionality
sys.path.insert(0, '/opt/netguard/sensors/lib')
from safe_json import read_json_safe

app = FastAPI()
app.mount("/static", StaticFiles(directory="/opt/netguard/static"), name="static")

VERSION = "v2.0.0-unified"  # Version tracking

# ============================================================================
# OLD ENDPOINTS (Preserved - InfluxDB Traffic)
# ============================================================================

@app.get("/api/state")
def get_state():
    """OLD: Traffic data from InfluxDB (UP/DOWN bytes per IP)"""
    try:
        token = pathlib.Path("/opt/netguard/secrets/influx_admin.token").read_text().strip()
        flux = 'from(bucket: "network_stats") |> range(start: -10m) |> filter(fn: (r) => r._measurement == "traffic")'
        r = requests.post("http://127.0.0.1:8086/api/v2/query?org=netguard",
            headers={"Authorization": f"Token {token}", "Accept": "application/csv", "Content-type": "application/vnd.flux"},
            data=flux, timeout=5)
        
        data_map = {}
        for line in r.text.splitlines():
            parts = [p.strip() for p in line.split(',')]
            if len(parts) >= 7 and parts[1] == "_result":
                ip, field = parts[6], parts[5]
                val = int(float(parts[4])) if parts[4] else 0
                if ip not in data_map: data_map[ip] = {"up": 0, "down": 0}
                if field in ['up', 'down']: data_map[ip][field] += val

        cards = [{"ip": ip, "up": s['up'], "down": s['down']} for ip, s in data_map.items()]
        return {"ip_cards": sorted(cards, key=lambda x: (x["up"]+x["down"]), reverse=True)}
    except Exception as e: 
        return {"ip_cards": [], "error": str(e)}

@app.get("/api/wifi_scan")
def get_wifi():
    """OLD: WiFi scan data"""
    try:
        return json.loads(pathlib.Path("/var/lib/netguard/wifi_scan.json").read_text())
    except: 
        return {"networks": []}

@app.get("/api/ai_thoughts")
def get_ai_thoughts():
    """OLD: AI thoughts from log file"""
    try:
        return {"lines": pathlib.Path("/var/lib/netguard/ai_thoughts.log").read_text().splitlines()[-15:]}
    except: 
        return {"lines": ["AI Security Guard Active"]}

# ============================================================================
# NEW ENDPOINTS (Device Security Monitoring)
# ============================================================================

@app.get("/api/devices")
def get_devices():
    """NEW: Real device data from router telemetry"""
    telemetry = read_json_safe('/var/lib/netguard/router_telemetry.json', {})
    findings = read_json_safe('/var/lib/netguard/router_findings.json', {})
    inventory = read_json_safe('/var/lib/netguard/router_inventory.json', {})
    
    if not telemetry.get('ok'):
        return {'devices': [], 'count': 0, 'error': telemetry.get('error', 'Telemetry unavailable')}
    
    clients = telemetry.get('clients', {}) or {}
    leases = clients.get('dhcp_leases', []) or []
    arp = clients.get('arp', []) or []
    reservations = inventory.get('reservations', []) or []
    
    devices = []
    for lease in leases:
        mac = lease.get('mac', '').lower()
        if not mac:
            continue
        
        ip = lease.get('ip', '')
        hostname = lease.get('hostname', 'Unknown')
        
        # Check against real inventory
        reserved = next((r for r in reservations if r.get('mac', '').lower() == mac), None)
        
        # Find real alerts
        device_alerts = []
        for alert in findings.get('alerts', []) or []:
            alert_str = str(alert)
            if mac in alert_str or ip in alert_str:
                device_alerts.append(alert)
        
        # Check real ARP status
        arp_entry = next((a for a in arp if a.get('mac', '').lower() == mac), None)
        
        devices.append({
            'mac': mac,
            'ip': ip,
            'hostname': hostname,
            'known': reserved is not None,
            'reserved_name': reserved.get('name', '') if reserved else '',
            'reachable': arp_entry is not None,
            'alerts': device_alerts,
            'alert_count': len(device_alerts)
        })
    
    return {'devices': devices, 'count': len(devices)}

@app.get("/api/status")
def api_status():
    """NEW: System health status"""
    telemetry = read_json_safe('/var/lib/netguard/router_telemetry.json', {})
    findings = read_json_safe('/var/lib/netguard/router_findings.json', {})
    health = read_json_safe('/var/lib/netguard/health.json', {})
    ai_state = read_json_safe('/var/lib/netguard/ai_guard_state.json', {})
    
    return {
        'version': VERSION,
        'telemetry_ok': telemetry.get('ok', False),
        'active_alerts': len(findings.get('alerts', [])),
        'health_status': health.get('status', 'unknown'),
        'ai_active': len(ai_state.get('thoughts', [])) > 0,
        'last_update': telemetry.get('generated_at', 'unknown')
    }

@app.get("/api/findings")
def get_findings():
    """NEW: Security findings and alerts"""
    findings = read_json_safe('/var/lib/netguard/router_findings.json', {})
    return findings

# ============================================================================
# HTML Endpoint
# ============================================================================

@app.get("/", response_class=HTMLResponse)
def root():
    html_path = pathlib.Path("/opt/netguard/static/ng_live.html")
    return html_path.read_text()

@app.get("/v2", response_class=HTMLResponse)
def root_v2():
    """NEW: Enhanced cyberpunk interface"""
    html_path = pathlib.Path("/opt/netguard/static/ng_unified.html")
    return html_path.read_text()
