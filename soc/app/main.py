from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import requests
from fastapi import FastAPI
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

BASE_DIR = Path(__file__).resolve().parents[1]
STATIC_DIR = BASE_DIR / "static"
CONF_DIR = BASE_DIR / "config"
STATE_DIR = Path("/var/lib/netguard")

SOC_VERSION = os.getenv("SOC_VERSION", "0.0")
INFLUX_URL = os.getenv("INFLUX_URL", "http://127.0.0.1:8086")
GRAFANA_URL = os.getenv("GRAFANA_URL", "http://127.0.0.1:3000")

DEVICES_FILE = CONF_DIR / "devices.json"
WIFI_SCAN_FILE = STATE_DIR / "wifi_scan.json"
MIRROR_STREAM_FILE = STATE_DIR / "mirror_stream.json"
AI_THOUGHTS_FILE = STATE_DIR / "ai_thoughts.json"

app = FastAPI(title="NetGuard SOC", version=SOC_VERSION)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/")
def root():
    return RedirectResponse(url="/static/ng_live.html")

def _read_json(path: Path, default: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        pass
    return default

def _stack_health() -> Dict[str, Any]:
    out: Dict[str, Any] = {"generated_at": utc_now_iso(), "influx": {"ok": False}, "grafana": {"ok": False}}
    # Influx
    try:
        r = requests.get(f"{INFLUX_URL.rstrip('/')}/health", timeout=1.5)
        out["influx"] = {"ok": r.ok, "status_code": r.status_code, "body": r.json() if r.ok else r.text[:200]}
    except Exception as e:
        out["influx"] = {"ok": False, "error": str(e)[:200]}
    # Grafana
    try:
        r = requests.get(f"{GRAFANA_URL.rstrip('/')}/api/health", timeout=1.5)
        out["grafana"] = {"ok": r.ok, "status_code": r.status_code, "body": r.json() if r.ok else r.text[:200]}
    except Exception as e:
        out["grafana"] = {"ok": False, "error": str(e)[:200]}
    return out

@app.get("/api/state")
def api_state():
    devices: List[Dict[str, Any]] = _read_json(DEVICES_FILE, [])
    # Passive-only: we do NOT ping/scan. Cards exist immediately; “online/offline” comes later from sensors.
    ip_cards = [{
        "ip": d.get("ip",""),
        "name": d.get("name",""),
        "mac": d.get("mac",""),
        "is_static": True,
        "shield": "gray",
        "ai_verdict": "UNSCORED",
        "ai_suggestion": "Waiting for sensor data (mirror + wifi scanners).",
        "threat_pct": 0
    } for d in devices if d.get("ip")]

    return JSONResponse({
        "generated_at": utc_now_iso(),
        "soc_version": SOC_VERSION,
        "stack_health": _stack_health(),   # footer consumes this
        "ip_cards": ip_cards
    })

@app.get("/api/wifi_scan")
def api_wifi_scan():
    # STEP 4 will populate this file via timer/service
    return JSONResponse(_read_json(WIFI_SCAN_FILE, {"generated_at": utc_now_iso(), "networks": [], "meta": {}}))

@app.get("/api/mirror_stream")
def api_mirror_stream():
    # STEP 5 will populate this file via mirror sensor
    return JSONResponse(_read_json(MIRROR_STREAM_FILE, {"generated_at": utc_now_iso(), "lines": []}))

@app.get("/api/ai_thoughts")
def api_ai_thoughts():
    # STEP 6+ will populate this file via AI/RAG
    return JSONResponse(_read_json(AI_THOUGHTS_FILE, {"generated_at": utc_now_iso(), "lines": ["AI engine not installed yet."]}))


# NETGUARD_ROUTER_AND_SERVICES_API_V1
def _utc_now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()

def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None

def _file_meta(path: Path):
    now = time.time()
    if not path.exists():
        return {"exists": False, "age_s": None, "mtime": None, "path": str(path)}
    try:
        st = path.stat()
        age = max(0.0, now - st.st_mtime)
        return {"exists": True, "age_s": age, "mtime": st.st_mtime, "path": str(path)}
    except Exception:
        return {"exists": True, "age_s": None, "mtime": None, "path": str(path)}

def _systemd_unit_status(unit: str):
    try:
        cmd = ["systemctl","show",unit,"--no-pager",
               "-p","ActiveState","-p","SubState","-p","MainPID","-p","ExecMainPID","-p","Description"]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        if p.returncode != 0:
            return {"unit": unit, "ok": False, "active": "unknown", "sub": "unknown", "desc": "", "pid": 0}
        kv = {}
        for line in p.stdout.splitlines():
            if "=" in line:
                k,v = line.split("=",1)
                kv[k.strip()] = v.strip()
        pid = int(kv.get("ExecMainPID") or kv.get("MainPID") or "0" or 0)
        return {"unit": unit, "ok": True, "active": kv.get("ActiveState","unknown"),
                "sub": kv.get("SubState","unknown"), "desc": kv.get("Description",""), "pid": pid}
    except Exception:
        return {"unit": unit, "ok": False, "active": "unknown", "sub": "unknown", "desc": "", "pid": 0}

_ROUTER_FILES = {
  "telemetry": Path("/var/lib/netguard/router_telemetry.json"),
  "findings":  Path("/var/lib/netguard/router_findings.json"),
  "ai":        Path("/var/lib/netguard/router_ai.json"),
  "ai_alt":    Path("/var/lib/netguard/router_ai_watch.json"),
  "inventory": Path("/var/lib/netguard/router_inventory.json"),
  "baseline":  Path("/var/lib/netguard/router_baseline.json"),
}

_DEFAULT_UNITS = [
  "netguard-soc.service",
  "netguard-router-telemetry.service",
  "netguard-router-telemetry.timer",
  "netguard-router-anomaly.service",
  "netguard-router-anomaly.timer",
  "netguard-router-ai.service",
  "netguard-router-ai.timer",
  "netguard-router-syslog.service",
  "netguard-router-syslog.timer",
]

@app.get("/api/router")
def api_router_bundle():
    ai_path = _ROUTER_FILES["ai"] if _ROUTER_FILES["ai"].exists() else _ROUTER_FILES["ai_alt"]
    files = {
      "telemetry": _ROUTER_FILES["telemetry"],
      "findings":  _ROUTER_FILES["findings"],
      "ai":        ai_path,
      "inventory": _ROUTER_FILES["inventory"],
      "baseline":  _ROUTER_FILES["baseline"],
    }

    out = {"generated_at": _utc_now_iso(), "soc_version": os.getenv("SOC_VERSION",""), "router": {}, "meta": {}}

    meta = {}
    for k, path in files.items():
        meta[k] = _file_meta(path)
    out["meta"] = meta

    out["router"]["telemetry"] = _read_json(files["telemetry"]) or {}
    out["router"]["findings"]  = _read_json(files["findings"])  or {}
    out["router"]["inventory"] = _read_json(files["inventory"]) or {}
    out["router"]["baseline"]  = _read_json(files["baseline"])  or {}
    ai = _read_json(files["ai"]) or {}
    out["router"]["ai"] = ai

    findings = out["router"]["findings"] if isinstance(out["router"]["findings"], dict) else {}
    summ = findings.get("summary") or {}
    alerts = findings.get("alerts") or []
    out["summary"] = {
      "risk": ai.get("risk"),
      "risk_level": ai.get("risk_level"),
      "alerts": alerts if isinstance(alerts, list) else [],
      "summary": summ if isinstance(summ, dict) else {},
      "stale": {
        "telemetry_age_s": meta["telemetry"]["age_s"],
        "findings_age_s":  meta["findings"]["age_s"],
        "ai_age_s":        meta["ai"]["age_s"],
      }
    }
    return out

@app.get("/api/services")
def api_services():
    units_env = os.getenv("NG_FOOTER_UNITS","").strip()
    units = [u.strip() for u in units_env.split(",") if u.strip()] if units_env else _DEFAULT_UNITS
    statuses = [_systemd_unit_status(u) for u in units]
    return {"generated_at": _utc_now_iso(), "soc_version": os.getenv("SOC_VERSION",""), "units": statuses}
