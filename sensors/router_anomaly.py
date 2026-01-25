#!/usr/bin/env python3
import os, json
from pathlib import Path
from datetime import datetime, timezone

TEL_PATH = Path(os.getenv("TEL_JSON", "/var/lib/netguard/router_telemetry.json"))
OUT_PATH = Path(os.getenv("OUT_JSON", "/var/lib/netguard/router_findings.json"))
BASE_PATH = Path(os.getenv("BASE_JSON", "/var/lib/netguard/router_baseline.json"))

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def load_json(path: Path):
    try:
        if not path.exists():
            return None
        s = path.read_text(encoding="utf-8", errors="replace").strip()
        if not s:
            return None
        return json.loads(s)
    except Exception:
        return None

def write_json(path: Path, obj: dict):
    path.write_text(json.dumps(obj, indent=2, sort_keys=False) + "\n", encoding="utf-8")

def is_zero_mac(mac: str) -> bool:
    return (mac or "").lower() in ("00:00:00:00:00:00", "00-00-00-00-00-00", "")

def wifi_assoc_from_telemetry(t: dict) -> dict:
    bands = (t.get("wifi") or {}).get("bands") or {}
    out = {}
    for b in ("wl0","wl1","wl2"):
        x = bands.get(b) or {}
        c = x.get("assoc_count")
        if c is None:
            c = x.get("assoc")
        if c is None:
            am = x.get("assoc_macs")
            c = len(am) if isinstance(am, list) else 0
        try:
            out[b] = int(c or 0)
        except Exception:
            out[b] = 0
    return out

def devices_from_telemetry(t: dict) -> dict:
    """Return mac -> {ip, hostname, lease_expiry_epoch, seen_via} preferring DHCP leases."""
    devices = {}

    leases = ((t.get("clients") or {}).get("dhcp_leases") or [])
    for l in leases:
        mac = (l.get("mac") or "").lower()
        if is_zero_mac(mac):
            continue
        devices.setdefault(mac, {})
        devices[mac].update({
            "mac": mac,
            "ip": l.get("ip") or "",
            "hostname": l.get("hostname") or "",
            "lease_expiry_epoch": l.get("expiry_epoch"),
            "seen_via": "dhcp",
        })

    # optional ARP supplement (only fills missing MACs)
    arps = ((t.get("clients") or {}).get("arp") or [])
    for a in arps:
        mac = (a.get("mac") or a.get("lladdr") or "").lower()
        ip  = (a.get("ip") or "").strip()
        if is_zero_mac(mac) or not ip:
            continue
        if mac not in devices:
            devices[mac] = {"mac": mac, "ip": ip, "hostname": "", "seen_via": "arp"}

    return devices

def baseline_devices(base: dict) -> dict:
    """baseline schema: { generated_at, devices: { mac: {ip, hostname} } }"""
    d = (base or {}).get("devices") or {}
    out = {}
    for mac, rec in d.items():
        mac2 = (mac or "").lower()
        if is_zero_mac(mac2):
            continue
        out[mac2] = {
            "mac": mac2,
            "ip": (rec or {}).get("ip") or "",
            "hostname": (rec or {}).get("hostname") or "",
        }
    return out

def main():
    out = {
        "generated_at": utc_now(),
        "ok": True,
        "error": "",
        "alerts": [],
        "changes": {
            "new_devices": [],
            "gone_devices": [],
            "ip_changes": [],
            "hostname_changes": [],
            "wifi_moves": []
        },
        "summary": {
            "dhcp_leases": 0,
            "arp_macs": 0,
            "wifi_assoc": {"wl0":0,"wl1":0,"wl2":0}
        }
    }

    t = load_json(TEL_PATH) or {}
    if not t or t.get("ok") is False:
        out["ok"] = False
        out["error"] = (t.get("error") if isinstance(t, dict) else "") or f"telemetry missing or invalid: {TEL_PATH}"
        write_json(OUT_PATH, out)
        return 0

    cur = devices_from_telemetry(t)
    base = baseline_devices(load_json(BASE_PATH) or {})

    # summary
    out["summary"]["dhcp_leases"] = len(((t.get("clients") or {}).get("dhcp_leases") or []))
    out["summary"]["arp_macs"] = len(((t.get("clients") or {}).get("arp") or []))
    out["summary"]["wifi_assoc"] = wifi_assoc_from_telemetry(t)

    # diffs
    cur_macs = set(cur.keys())
    base_macs = set(base.keys())

    new_macs = sorted(cur_macs - base_macs)
    gone_macs = sorted(base_macs - cur_macs)

    for mac in new_macs:
        rec = cur[mac]
        out["changes"]["new_devices"].append({
            "mac": mac,
            "ip": rec.get("ip",""),
            "hostname": rec.get("hostname",""),
            "lease_expiry_epoch": rec.get("lease_expiry_epoch"),
            "seen_via": rec.get("seen_via",""),
        })

    for mac in gone_macs:
        rec = base[mac]
        out["changes"]["gone_devices"].append({
            "mac": mac,
            "last_ip": rec.get("ip",""),
            "last_hostname": rec.get("hostname",""),
        })

    for mac in sorted(cur_macs & base_macs):
        c = cur[mac]
        b = base[mac]
        cip, bip = c.get("ip",""), b.get("ip","")
        chn, bhn = (c.get("hostname","") or ""), (b.get("hostname","") or "")
        if cip and bip and cip != bip:
            out["changes"]["ip_changes"].append({"mac": mac, "from": bip, "to": cip})
        if chn and bhn and chn != bhn:
            out["changes"]["hostname_changes"].append({"mac": mac, "from": bhn, "to": chn})

    # alerts (simple + useful)
    if out["changes"]["new_devices"]:
        out["alerts"].append({
            "severity":"medium","kind":"new_device","count":len(out["changes"]["new_devices"]),
            "examples":[x["mac"] for x in out["changes"]["new_devices"][:8]]
        })
    if out["changes"]["ip_changes"]:
        out["alerts"].append({
            "severity":"low","kind":"ip_change","count":len(out["changes"]["ip_changes"]),
            "examples":[f'{x["mac"]}:{x["from"]}->{x["to"]}' for x in out["changes"]["ip_changes"][:6]]
        })
    if out["changes"]["gone_devices"]:
        out["alerts"].append({
            "severity":"low","kind":"gone_device","count":len(out["changes"]["gone_devices"]),
            "examples":[x["mac"] for x in out["changes"]["gone_devices"][:8]]
        })

    write_json(OUT_PATH, out)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
