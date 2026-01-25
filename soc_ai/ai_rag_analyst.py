#!/usr/bin/env python3
import json, time, urllib.request, urllib.error
from pathlib import Path
from rag_store import init_db, search_docs, metric_series, record_ai

DB = "/var/lib/netguard/rag/netguard_memory.db"
AI_RAG_STATE = Path("/var/lib/netguard/ai_rag_state.json")

TELEMETRY = Path("/var/lib/netguard/router_telemetry.json")
FINDINGS  = Path("/var/lib/netguard/router_findings.json")
WIFIASSOC = Path("/var/lib/netguard/router_wifi_assoc.json")

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL = "llama3.2:latest"

def _read(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}

def _ollama(prompt: str) -> str:
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
            "num_predict": 220
        }
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(OLLAMA_URL, data=data, headers={"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            out = json.loads(resp.read().decode("utf-8", errors="replace"))
            return (out.get("response") or "").strip()
    except Exception as e:
        return f"[ollama_error] {e}"

def _trend(name: str, hours: int=24):
    now = int(time.time())
    since = now - hours*3600
    pts = metric_series(DB, name, since)
    if not pts:
        return {"name": name, "points": 0}
    vals = [v for _, v in pts]
    return {
        "name": name,
        "points": len(pts),
        "min": min(vals),
        "max": max(vals),
        "last": vals[-1],
    }

def main():
    init_db(DB)
    tel = _read(TELEMETRY)
    fin = _read(FINDINGS)
    wifi = _read(WIFIASSOC)

    # Current snapshot facts (REAL)
    leases = (tel.get("clients", {}) or {}).get("dhcp_leases", []) or []
    details = fin.get("details", {}) or {}
    unknown = details.get("unknown", []) or []
    drift   = details.get("reserved_drift", []) or []
    bases = ((wifi.get("wifi", {}) or {}).get("bases", {}) or {})
    wl0 = (bases.get("wl0", {}) or {}).get("assoc_count", 0)
    wl1 = (bases.get("wl1", {}) or {}).get("assoc_count", 0)
    wl2 = (bases.get("wl2", {}) or {}).get("assoc_count", 0)

    # Trends
    t_unknown = _trend("unknown_devices_count", 24)
    t_alerts  = _trend("alerts_count", 24)
    t_wl0     = _trend("wifi_wl0_assoc_count", 24)
    t_wl1     = _trend("wifi_wl1_assoc_count", 24)
    t_mem     = _trend("router_mem_used_pct", 24)

    # Retrieval targets (keep light)
    q = "unknown device randomized mac reservation drift wifi security wps wpa3 vlan channel utilization"
    docs = search_docs(DB, q, limit=4)

    kb = "\n\n".join([f"## {d['title']}\n{d['body'][:900]}" for d in docs])

    # Prompt: make it explicitly a NetGuard network/security optimizer
    prompt = f"""
You are NetGuard SOC AI, a PASSIVE network security + performance optimization advisor.
You do NOT auto-change the router. You only recommend safe next steps grounded in REAL telemetry + trends.
Output format: 4 short lines max. Each line must start with one tag:
[OBS] observed fact  |  [RISK] risk assessment  |  [SUGGEST] action  |  [OPT] performance suggestion

CURRENT SNAPSHOT (REAL):
- DHCP leases: {len(leases)}
- Unknown devices now: {len(unknown)}
- Reservation drift now: {len(drift)}
- WiFi assoc now: wl0(2.4)={wl0} wl1(5)={wl1} wl2(6)={wl2}

UNKNOWN DEVICES (up to 3):
{json.dumps(unknown[:3], separators=(",",":"))}

TRENDS (24h):
- unknown_devices_count: {t_unknown}
- alerts_count: {t_alerts}
- wifi_wl0_assoc_count: {t_wl0}
- wifi_wl1_assoc_count: {t_wl1}
- router_mem_used_pct: {t_mem}

LOCAL PLAYBOOK / KNOWLEDGE (RAG):
{kb}
""".strip()

    resp = _ollama(prompt)

    now = int(time.time())
    thoughts = []
    for line in resp.splitlines():
        line = line.strip()
        if not line:
            continue
        level = "info"
        if line.startswith("[RISK]"):
            level = "warning"
        if line.startswith("[SUGGEST]"):
            level = "suggestion"
        if line.startswith("[OBS]"):
            level = "info"
        if line.startswith("[OPT]"):
            level = "info"

        thought = line.replace("[OBS]","").replace("[RISK]","").replace("[SUGGEST]","").replace("[OPT]","").strip()
        if thought:
            thoughts.append({
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "level": level,
                "thought": f"🧠 RAG: {thought}"
            })
            record_ai(DB, level, thought, context={"unknown_now": len(unknown), "drift_now": len(drift)} , ts=now)

    # Write state file (separate from ai_guard_state.json to avoid races)
    state = {
        "ok": True,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "model": MODEL,
        "thoughts": thoughts[-12:]
    }
    AI_RAG_STATE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    print("OK")

if __name__ == "__main__":
    main()
