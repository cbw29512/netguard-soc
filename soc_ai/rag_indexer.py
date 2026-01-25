#!/usr/bin/env python3
import json, time, re
from pathlib import Path
from rag_store import init_db, upsert_doc, add_metric, prune

DB = "/var/lib/netguard/rag/netguard_memory.db"

TELEMETRY = Path("/var/lib/netguard/router_telemetry.json")
FINDINGS  = Path("/var/lib/netguard/router_findings.json")
SYSLOGF   = Path("/var/lib/netguard/router_syslog_findings.json")
WIFIASSOC = Path("/var/lib/netguard/router_wifi_assoc.json")
INVENTORY = Path("/var/lib/netguard/router_inventory.json")
HEALTH    = Path("/var/lib/netguard/health.json")

def _read(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}

def _safe_int(x, d=0):
    try: return int(x)
    except Exception: return d

def summarize():
    tel = _read(TELEMETRY)
    fin = _read(FINDINGS)
    sysf = _read(SYSLOGF)
    wifi = _read(WIFIASSOC)
    inv = _read(INVENTORY)
    hlt = _read(HEALTH)

    now = int(time.time())

    # --- Core counts ---
    leases = (tel.get("clients", {}) or {}).get("dhcp_leases", []) or []
    arp    = (tel.get("clients", {}) or {}).get("arp", []) or []
    alerts = fin.get("alerts", []) or []
    details = fin.get("details", {}) or {}

    unknown = details.get("unknown", []) or []
    drift   = details.get("reserved_drift", []) or []

    add_metric(DB, "dhcp_leases_count", len(leases), ts=now)
    add_metric(DB, "arp_count", len(arp), ts=now)
    add_metric(DB, "alerts_count", len(alerts), ts=now)
    add_metric(DB, "unknown_devices_count", len(unknown), ts=now)
    add_metric(DB, "ip_drift_count", len(drift), ts=now)

    # --- Router stats ---
    r = tel.get("router", {}) or {}
    loadavg = (r.get("loadavg", "") or "0 0 0").split()
    if len(loadavg) >= 1: add_metric(DB, "router_load_1", float(loadavg[0]), ts=now)
    if len(loadavg) >= 2: add_metric(DB, "router_load_5", float(loadavg[1]), ts=now)
    if len(loadavg) >= 3: add_metric(DB, "router_load_15", float(loadavg[2]), ts=now)

    # meminfo parsing (kB)
    meminfo = r.get("meminfo", "") or ""
    mt = ma = None
    for line in meminfo.splitlines():
        if line.startswith("MemTotal:"):
            mt = _safe_int(re.search(r"(\d+)", line).group(1))
        if line.startswith("MemAvailable:"):
            ma = _safe_int(re.search(r"(\d+)", line).group(1))
    if mt and ma is not None:
        used_pct = (1.0 - (ma/mt)) * 100.0
        add_metric(DB, "router_mem_used_pct", used_pct, ts=now)

    # --- WiFi assoc counts (REAL from router_wifi_assoc.json) ---
    bases = ((wifi.get("wifi", {}) or {}).get("bases", {}) or {})
    for iface in ("wl0","wl1","wl2"):
        info = bases.get(iface, {}) or {}
        add_metric(DB, f"wifi_{iface}_assoc_count", float(info.get("assoc_count", 0) or 0), ts=now)

    # --- Health ---
    status = (hlt.get("status") or "unknown").lower()
    add_metric(DB, "health_ok", 1.0 if status == "healthy" else 0.0, ts=now)

    # --- Build a compact “snapshot doc” for retrieval ---
    gen_at = tel.get("generated_at") or tel.get("router", {}).get("generated_at") or ""
    doc_id = f"snapshot:{gen_at or now}"
    title  = f"NetGuard Snapshot @ {gen_at or time.strftime('%Y-%m-%d %H:%M:%S')}"
    # include key evidence lines (REAL data only)
    wl0 = bases.get("wl0", {}) or {}
    wl1 = bases.get("wl1", {}) or {}
    wl2 = bases.get("wl2", {}) or {}
    body_lines = [
        f"DHCP leases: {len(leases)}",
        f"ARP entries: {len(arp)}",
        f"Alerts: {len(alerts)} | Unknown devices: {len(unknown)} | IP drift: {len(drift)}",
        f"WiFi assoc counts: wl0(2.4)={wl0.get('assoc_count',0)} wl1(5)={wl1.get('assoc_count',0)} wl2(6)={wl2.get('assoc_count',0)}",
        f"Router loadavg: {r.get('loadavg','')}".strip(),
        f"Router uptime: {r.get('uptime','')}".strip(),
    ]
    # include unknown devices list (if any)
    for u in unknown[:8]:
        body_lines.append(f"UNKNOWN: {u.get('hostname','?')} ip={u.get('ip','?')} mac={u.get('mac','?')}")
    for d in drift[:8]:
        body_lines.append(f"DRIFT: {d.get('name','?')} mac={d.get('mac','?')} expected={d.get('want')} got={d.get('got')}")

    upsert_doc(DB, doc_id, "snapshot", title, "\n".join([x for x in body_lines if x]), created_at=now)

    # prune older stuff
    prune(DB, keep_days=14)

def ingest_knowledge():
    from rag_store import upsert_doc
    know_dir = Path("/var/lib/netguard/rag/knowledge")
    now = int(time.time())
    for p in sorted(know_dir.glob("*.md")):
        doc_id = f"knowledge:{p.name}"
        upsert_doc(DB, doc_id, "knowledge", p.stem, p.read_text(encoding="utf-8", errors="replace"), created_at=now)

if __name__ == "__main__":
    init_db(DB)
    ingest_knowledge()
    summarize()
    print("OK")
