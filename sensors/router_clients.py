#!/usr/bin/env python3
import os, json, subprocess, re
from datetime import datetime, timezone
from pathlib import Path

ENVF = Path("/opt/netguard/sensors/router_clients.env")
OUT  = Path("/var/lib/netguard/router_clients.json")

def load_env():
    env = {}
    if ENVF.exists():
        for line in ENVF.read_text(encoding="utf-8", errors="replace").splitlines():
            line=line.strip()
            if not line or line.startswith("#") or "=" not in line: 
                continue
            k,v=line.split("=",1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def run_ssh(user, host, opts):
    # Router-side shell: enumerate wl0/wl1/wl2 if present, list assoc clients, label band via `wl band`
    script = r'''
out=""
for i in 0 1 2 3; do
  if wl -i wl$i band >/dev/null 2>&1; then
    b="$(wl -i wl$i band 2>/dev/null | tr -d '\r' | tr '[:upper:]' '[:lower:]')"
    # normalize
    case "$b" in
      *2g*) band="2.4" ;;
      *5g*) band="5" ;;
      *6g*) band="6" ;;
      *) band="$b" ;;
    esac
    wl -i wl$i assoclist 2>/dev/null | while read -r _ mac; do
      [ -n "$mac" ] || continue
      echo "band=$band mac=$mac radio=wl$i"
    done
  fi
done
'''
    cmd = ["ssh"] + (opts.split() if opts else []) + [f"{user}@{host}", "sh", "-lc", script]
    p = subprocess.run(cmd, text=True, capture_output=True)
    return p.returncode, (p.stdout or ""), (p.stderr or "")

def atomic_write(path: Path, obj: dict):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    tmp.replace(path)

def main():
    env = load_env()
    host = env.get("ROUTER_HOST","").strip()
    user = env.get("ROUTER_USER","").strip()
    opts = env.get("SSH_OPTS","").strip()

    payload = {"generated_at": utc_now(), "ok": False, "clients": [], "error": None}

    if not host or not user:
        payload["error"] = "Missing ROUTER_HOST/ROUTER_USER in router_clients.env"
        atomic_write(OUT, payload); return

    rc, out, err = run_ssh(user, host, opts)

    if rc != 0:
        payload["error"] = f"ssh failed rc={rc}: {err.strip()[:200]}"
        atomic_write(OUT, payload); return

    clients = []
    for line in out.splitlines():
        # band=5 mac=aa:bb:cc:dd:ee:ff radio=wl1
        m = re.findall(r"(\w+)=([^\s]+)", line.strip())
        if not m: 
            continue
        d = {k:v for k,v in m}
        if "mac" in d:
            d["mac"] = d["mac"].lower()
            clients.append(d)

    payload["ok"] = True
    payload["clients"] = clients
    atomic_write(OUT, payload)

if __name__ == "__main__":
    main()
