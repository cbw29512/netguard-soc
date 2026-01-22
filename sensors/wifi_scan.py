from __future__ import annotations
import json, os, re, subprocess, time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

STATE_DIR = Path(os.getenv("STATE_DIR", "/var/lib/netguard"))
OUT = STATE_DIR / "wifi_scan.json"

WIFI24_IFACE = os.getenv("WIFI24_IFACE", "wlx00c0cab95938")
WIFI5_IFACE  = os.getenv("WIFI5_IFACE",  "wlx00c0caafbb83")

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def run(cmd: List[str], timeout: float = 12.0) -> str:
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
    return p.stdout

def freq_to_band(freq: int) -> str:
    return "2.4" if freq < 3000 else "5"

def freq_to_channel(freq: int) -> Optional[int]:
    # 2.4 GHz
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if freq == 2484:
        return 14
    # 5 GHz common (includes DFS)
    if 5000 <= freq <= 5900:
        return (freq - 5000) // 5
    return None

@dataclass
class Net:
    ssid: str
    bssid: str
    freq_mhz: int
    signal_dbm: int
    channel: Optional[int]
    band: str
    source_iface: str

def parse_iw_scan(txt: str, iface: str) -> List[Net]:
    # Split into BSS blocks
    blocks = re.split(r"\n(?=BSS\s)", txt)
    out: List[Net] = []
    for b in blocks:
        m_bss = re.search(r"^BSS\s+([0-9a-f:]{17})", b, re.IGNORECASE | re.MULTILINE)
        if not m_bss:
            continue
        bssid = m_bss.group(1).lower()

        m_freq = re.search(r"^\s*freq:\s*(\d+)\s*$", b, re.MULTILINE)
        if not m_freq:
            continue
        freq = int(m_freq.group(1))

        m_sig = re.search(r"^\s*signal:\s*([-\d\.]+)\s*dBm", b, re.MULTILINE)
        sig = int(float(m_sig.group(1))) if m_sig else -100

        m_ssid = re.search(r"^\s*SSID:\s*(.*)$", b, re.MULTILINE)
        ssid = (m_ssid.group(1).strip() if m_ssid else "")
        if ssid == "":
            ssid = "<hidden>"

        band = freq_to_band(freq)
        ch = freq_to_channel(freq)

        out.append(Net(
            ssid=ssid[:64],
            bssid=bssid,
            freq_mhz=freq,
            signal_dbm=sig,
            channel=ch,
            band=band,
            source_iface=iface,
        ))
    return out

def scan_iface(iface: str) -> Dict[str, Any]:
    if iface.strip() == "":
        return {"ok": False, "error": "empty iface"}
    try:
        # -u = include frequency, signal, etc.
        txt = run(["iw", "dev", iface, "scan", "-u"], timeout=14.0)
        nets = parse_iw_scan(txt, iface)
        return {"ok": True, "count": len(nets), "nets": [n.__dict__ for n in nets]}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200], "count": 0, "nets": []}

def atomic_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(path)

def main() -> int:
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    meta: Dict[str, Any] = {"generated_at": utc_now_iso(), "ifaces": {}, "note": "iw scan (managed mode)."}
    networks: List[Dict[str, Any]] = []

    # Scan both (dedicated) adapters
    for iface in [WIFI24_IFACE, WIFI5_IFACE]:
        res = scan_iface(iface)
        meta["ifaces"][iface] = {k: v for k, v in res.items() if k != "nets"}
        networks.extend(res.get("nets", []))

    # Sort for readability: strongest first
    networks.sort(key=lambda x: int(x.get("signal_dbm", -100)), reverse=True)

    payload = {"generated_at": meta["generated_at"], "networks": networks, "meta": meta}
    atomic_write_json(OUT, payload)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
