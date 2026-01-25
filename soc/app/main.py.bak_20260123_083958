from __future__ import annotations
import json
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List

import requests
from fastapi import FastAPI
from fastapi.responses import RedirectResponse, JSONResponse
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
