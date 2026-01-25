#!/usr/bin/env python3
# NETGUARD_WIFI_SCAN_PARSER_V3_BANDLOCK
import os, json, subprocess, re
from datetime import datetime, timezone

OUT = os.getenv("WIFI_SCAN_OUT", "/var/lib/netguard/wifi_scan.json")

WIFI24_IFACE = os.getenv("WIFI24_IFACE", "wlx00c0cab95938")  # new -> 2.4 only
WIFI5_IFACE  = os.getenv("WIFI5_IFACE",  "wlx00c0caafbb83")  # old -> 5 only
REGDOMAIN    = os.getenv("REGDOMAIN", "US")

# 2.4 GHz channels 1-11 center freqs (US)
FREQS_24 = [2412,2417,2422,2427,2432,2437,2442,2447,2452,2457,2462]

# 5 GHz common US channel center freqs (non-DFS + DFS + upper)
FREQS_5 = [
    5180,5200,5220,5240,  # 36-48
    5260,5280,5300,5320,  # 52-64 (DFS)
    5500,5520,5540,5560,  # 100-112 (DFS)
    5580,5600,5620,5640,  # 116-128 (DFS)
    5660,5680,5700,5720,  # 132-144 (DFS; 144 may be allowed)
    5745,5765,5785,5805,5825  # 149-165
]

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def sh(cmd, timeout=20):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
    return p.returncode, p.stdout

def try_set_regdomain():
    if not REGDOMAIN:
        return
    # best effort; service also sets this
    try:
        sh(["iw", "reg", "set", REGDOMAIN], timeout=5)
    except Exception:
        pass

def freq_to_channel(freq_mhz: int) -> int | None:
    # 2.4 GHz
    if 2412 <= freq_mhz <= 2472:
        return int((freq_mhz - 2407) / 5)
    if freq_mhz == 2484:
        return 14
    # 5 GHz
    if 5000 <= freq_mhz < 5900:
        return int((freq_mhz - 5000) / 5)
    # 6 GHz (not used here)
    if 5900 <= freq_mhz < 7200:
        return int((freq_mhz - 5950) / 5)
    return None

def band_from_freq(freq_mhz: int) -> str:
    if freq_mhz < 2500:
        return "2.4"
    if freq_mhz < 5900:
        return "5"
    return "6"

def parse_iw_scan(output: str, source_iface: str, expect_band: str):
    nets = []
    cur = None

    def flush():
        nonlocal cur
        if not cur:
            return
        # enforce band lock as a second line of defense
        f = cur.get("freq_mhz")
        if isinstance(f, int):
            b = band_from_freq(f)
            if expect_band == "2.4" and b != "2.4":
                cur = None
                return
            if expect_band == "5" and b != "5":
                cur = None
                return
        # fill band/channel if possible
        if isinstance(f, int):
            cur["band"] = band_from_freq(f)
            ch = freq_to_channel(f)
            if ch is not None:
                cur["channel"] = ch
        cur["source_iface"] = source_iface
        nets.append(cur)
        cur = None

    for raw in output.splitlines():
        line = raw.strip("\n")

        if line.startswith("BSS "):
            flush()
            # BSS aa:bb:cc:dd:ee:ff(on wlanX)
            m = re.match(r"^BSS\s+([0-9a-f:]{17})\(", line, flags=re.I)
            bssid = m.group(1).lower() if m else None
            cur = {"bssid": bssid, "ssid": "<hidden>", "signal_dbm": None, "freq_mhz": None}
            continue

        if cur is None:
            continue

        s = line.strip()

        if s.startswith("SSID:"):
            cur["ssid"] = s.split("SSID:", 1)[1].strip() or "<hidden>"
            continue

        if s.startswith("freq:"):
            # freq: 2427.0 or freq: 5200
            val = s.split("freq:", 1)[1].strip()
            try:
                cur["freq_mhz"] = int(round(float(val)))
            except Exception:
                pass
            continue

        if s.startswith("signal:"):
            # signal: -76.00 dBm
            m = re.search(r"signal:\s*([-]?\d+(?:\.\d+)?)\s*dBm", s, flags=re.I)
            if m:
                try:
                    cur["signal_dbm"] = int(round(float(m.group(1))))
                except Exception:
                    pass
            continue

    flush()

    # normalize fields + drop None bssid entries
    out = []
    for n in nets:
        if not n.get("bssid"):
            continue
        # prefer integers
        if n.get("signal_dbm") is None:
            n["signal_dbm"] = -100
        if n.get("freq_mhz") is None:
            continue
        # ensure band present
        n["band"] = n.get("band") or band_from_freq(n["freq_mhz"])
        out.append(n)

    return out

def scan_iface(iface: str, freqs: list[int], expect_band: str):
    # Limit scan to allowed freqs for this adapter
    cmd = ["iw", "dev", iface, "scan", "-u", "freq"] + [str(f) for f in freqs]
    rc, out = sh(cmd, timeout=25)
    meta = {"ok": (rc == 0), "rc": rc, "count": 0, "output_head": ""}
    nets = []
    if rc == 0:
        nets = parse_iw_scan(out, iface, expect_band)
        meta["count"] = len(nets)
    else:
        meta["error"] = "iw scan failed"
        meta["output_head"] = out[:300].replace("\r\n", "\n").replace("\r", "\n")
    return nets, meta

def main():
    try_set_regdomain()

    all_nets = []
    ifaces_meta = {}

    nets24, m24 = scan_iface(WIFI24_IFACE, FREQS_24, "2.4")
    all_nets.extend(nets24)
    ifaces_meta[WIFI24_IFACE] = m24

    nets5, m5 = scan_iface(WIFI5_IFACE, FREQS_5, "5")
    all_nets.extend(nets5)
    ifaces_meta[WIFI5_IFACE] = m5

    payload = {
        "generated_at": utc_now_iso(),
        "networks": all_nets,
        "meta": {
            "generated_at": utc_now_iso(),
            "ifaces": ifaces_meta,
            "note": "iw scan band-locked via explicit freq lists (2.4 vs 5).",
        },
    }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    tmp = OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=False)
    os.replace(tmp, OUT)

if __name__ == "__main__":
    main()
