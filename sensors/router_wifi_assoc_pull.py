#!/usr/bin/env python3
import os, json, subprocess, re
from datetime import datetime, timezone
from pathlib import Path

MAC_RE = re.compile(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        raise RuntimeError((p.stderr or "").strip() or f"cmd rc={p.returncode}")
    return p.stdout

def main():
    env = os.environ
    host = env.get("ROUTER_HOST","192.168.50.1")
    user = env.get("ROUTER_USER","nucboxr")
    port = env.get("ROUTER_SSH_PORT","22")
    key  = env.get("KEY_PATH","/var/lib/netguard/keys/netguard_router_ed25519")
    known= env.get("KNOWN_HOSTS","/var/lib/netguard/ssh_known_hosts")
    outp = Path(env.get("OUT_JSON","/var/lib/netguard/router_wifi_assoc.json"))

    out = {
        "generated_at": utc_now(),
        "ok": True,
        "error": "",
        "wifi": {"bases": {}},
    }

    try:
        # Router-side script:
        # - list wl ifnames
        # - for each, run wl -i IF assoclist and extract MACs
        script = r"""
set -eu
IFS="$(printf '\n\t')"

# list wl interfaces (wl0, wl0.1, wl1.2, etc.)
IFNAMES="$(ls /sys/class/net 2>/dev/null | grep -E '^wl[0-9]+(\.[0-9]+)?$' | sort || true)"

for IF in $IFNAMES; do
  # extract MACs robustly
  wl -i "$IF" assoclist 2>/dev/null | grep -Eo '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | while read -r MAC; do
    echo "$IF $MAC"
  done
done
"""
        ssh_cmd = [
            "ssh",
            "-i", key,
            "-p", port,
            "-o", f"UserKnownHostsFile={known}",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=5",
            f"{user}@{host}",
            "/bin/sh"
        ]

        raw = run(ssh_cmd + ["-c", script])

        bases = {}
        for line in raw.splitlines():
            parts = line.strip().split()
            if len(parts) != 2:
                continue
            ifname, mac = parts[0], parts[1].lower()
            if not MAC_RE.fullmatch(mac):
                continue
            base = ifname.split(".",1)[0]
            b = bases.setdefault(base, {"ifnames": set(), "assoc_macs": set()})
            b["ifnames"].add(ifname)
            b["assoc_macs"].add(mac)

        # finalize
        for base, d in bases.items():
            out["wifi"]["bases"][base] = {
                "assoc_count": len(d["assoc_macs"]),
                "assoc_macs": sorted(d["assoc_macs"]),
                "ifnames": sorted(d["ifnames"]),
            }

    except Exception as e:
        out["ok"] = False
        out["error"] = str(e)

    outp.write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps({"ok": out["ok"], "error": out["error"], "bases": list(out["wifi"]["bases"].keys())}))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
