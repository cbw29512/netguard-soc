#!/usr/bin/env python3
import json, os
from datetime import datetime, timezone
from pathlib import Path

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def read_json(p: Path, default):
    try:
        if not p.exists():
            return default
        return json.loads(p.read_text(errors="replace"))
    except Exception:
        return default

def write_json(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2) + "\n")

def main() -> int:
    out_json = Path(os.getenv("AI_JSON", "/var/lib/netguard/router_ai_brief.json"))
    tel_json = Path(os.getenv("TEL_JSON", "/var/lib/netguard/router_telemetry.json"))
    find_json= Path(os.getenv("FIND_JSON","/var/lib/netguard/router_findings.json"))
    sysf_json= Path(os.getenv("SYSF_JSON","/var/lib/netguard/router_syslog_findings.json"))

    tel = read_json(tel_json, {})
    f   = read_json(find_json, {})
    sysf= read_json(sysf_json, {})

    alerts = f.get("alerts") or []
    details= f.get("details") or {}
    summary= f.get("summary") or {}

    risk = 0
    notes = []
    actions = []

    # summarize basics
    notes.append(f'DHCP leases seen: {summary.get("dhcp_leases", 0)}.')
    wa = summary.get("wifi_assoc") or {}
    notes.append(f'Wi-Fi associations: wl0={wa.get("wl0",0)}, wl1={wa.get("wl1",0)}, wl2={wa.get("wl2",0)}.')

    # syslog notes (best-effort)
    if sysf.get("ok") is True:
        sup = sysf.get("summary",{}).get("ignored_expected_dropbear_from_nuc")
        if sup is not None:
            notes.append(f'Router syslog: expected NUC SSH noise suppressed ({sup} lines in window).')

    # scoring by alert kinds
    kind_map = {a.get("kind"): a for a in alerts}
    if "off_lan_ip" in kind_map:
        c = kind_map["off_lan_ip"].get("count", 1) or 1
        risk += 80 + min(20, int(c)*2)
        actions.append("Active off-LAN IP(s) detected. Check Guest/MLO DHCP/subnet settings and ensure LAN is the only DHCP domain if using a single-zone design.")
    if "reserved_ip_drift" in kind_map:
        c = kind_map["reserved_ip_drift"].get("count", 1) or 1
        risk += 40 + min(20, int(c)*3)
        # give concrete drift items
        drift = (details.get("reserved_drift") or [])[:5]
        if drift:
            d0 = ", ".join([f'{x.get("name","?")} {x.get("want")}→{x.get("got")}' for x in drift])
            notes.append(f"Reserved IP drift: {d0}")
        actions.append("Reserved IP drift: likely Private Wi-Fi Address/random MAC or stale DHCP lease. Fix by disabling Private Address for that SSID or updating reservation to the active MAC, then renew Wi-Fi lease (toggle Wi-Fi off/on).")
    if "unknown_device" in kind_map:
        c = kind_map["unknown_device"].get("count", 1) or 1
        risk += 30 + min(20, int(c)*3)
        actions.append("Unknown device(s) detected (non-private MAC). Verify ownership; if unexpected, block/denylist or change Wi-Fi password.")
    if "unknown_private_mac" in kind_map:
        c = kind_map["unknown_private_mac"].get("count", 1) or 1
        risk += 10 + min(20, int(c)*2)
        actions.append("Unknown private/random MAC(s) detected. Often iOS/Android ‘Private Address’. If it’s your device, either reserve that MAC or disable Private Address for stable identity.")

    if risk >= 70:
        level = "HIGH"
    elif risk >= 35:
        level = "MEDIUM"
    else:
        level = "LOW"

    out = {
        "generated_at": now_iso(),
        "ok": True,
        "risk_score": int(min(100, risk)),
        "risk_level": level,
        "notes": notes,
        "recommended_actions": actions,
        "pointers": {
            "telemetry": str(tel_json),
            "findings": str(find_json),
            "syslog_findings": str(sysf_json),
        },
    }
    write_json(out_json, out)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
