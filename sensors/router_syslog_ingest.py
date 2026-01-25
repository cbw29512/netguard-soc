#!/usr/bin/env python3
import os, re, json, sqlite3
from pathlib import Path
from datetime import datetime, timezone, timedelta

OUT_DIR = Path("/var/lib/netguard")
LOG     = Path("/var/log/asus-router/router.log")
DB      = Path(os.environ.get("NG_SYSLOG_DB", str(OUT_DIR/"router_syslog.sqlite")))
STATE   = Path(os.environ.get("NG_SYSLOG_STATE", str(OUT_DIR/"router_syslog.offset")))
OUTJSON = Path(os.environ.get("NG_SYSLOG_OUT", str(OUT_DIR/"router_syslog_findings.json")))

NUC_IP  = os.environ.get("NG_NUC_IP", "192.168.50.50")
WINDOW_MIN = int(os.environ.get("NG_SYSLOG_WINDOW_MIN", "10"))
MAX_ROWS = int(os.environ.get("NG_SYSLOG_MAX_ROWS", "20000"))

LINE = re.compile(r'^(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<prog>[^\[]+)\[(?P<pid>\d+)\]:\s+(?P<msg>.*)$')
DROPBEAR_CHILD = re.compile(r'Child connection from (?P<srcip>\d+\.\d+\.\d+\.\d+):(?P<srcport>\d+)')
DROPBEAR_FAIL  = re.compile(r'(?i)(bad password|password auth failed|login failed|permission denied)')

def utc_now():
    return datetime.now(timezone.utc)

def utc_now_iso():
    return utc_now().isoformat()

def ensure_db(conn: sqlite3.Connection) -> None:
    conn.execute("""
      CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, host TEXT, prog TEXT, pid INTEGER, msg TEXT, raw TEXT
      )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_id ON events(id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_prog ON events(prog)")
    conn.commit()

def read_offset() -> int:
    try:
        s = STATE.read_text().strip()
        return int(s) if s else 0
    except Exception:
        return 0

def write_offset(n: int) -> None:
    STATE.write_text(str(n))

def parse_line(line: str):
    m = LINE.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    try: d["pid"] = int(d["pid"])
    except Exception: d["pid"] = 0
    d["prog"] = (d["prog"] or "").strip()
    d["raw"] = line.rstrip("\n")
    return d

def is_expected_nuc_dropbear(prog: str, msg: str) -> bool:
    if prog != "dropbear":
        return False
    if f"from {NUC_IP}:" in msg: return True
    if f"<{NUC_IP}:" in msg: return True
    if f"Child connection from {NUC_IP}:" in msg: return True
    return False

def parse_ts(ts: str):
    # Router emits ISO like: 2026-01-22T19:43:20-05:00
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None

def ingest():
    LOG.parent.mkdir(parents=True, exist_ok=True)
    STATE.parent.mkdir(parents=True, exist_ok=True)

    off = read_offset()
    data = LOG.read_bytes() if LOG.exists() else b""
    if off > len(data):
        off = 0

    new = data[off:]
    if not new:
        return 0

    lines = new.decode("utf-8", errors="replace").splitlines(True)
    parsed = [d for d in (parse_line(ln) for ln in lines) if d]

    if parsed:
        conn = sqlite3.connect(DB)
        ensure_db(conn)
        conn.executemany(
            "INSERT INTO events(ts,host,prog,pid,msg,raw) VALUES (?,?,?,?,?,?)",
            [(d["ts"], d["host"], d["prog"], d["pid"], d["msg"], d["raw"]) for d in parsed]
        )
        conn.commit()
        conn.close()

    write_offset(len(data))
    return len(parsed)

def summarize():
    conn = sqlite3.connect(DB)
    ensure_db(conn)
    rows = conn.execute(
        "SELECT ts,host,prog,pid,msg FROM events ORDER BY id DESC LIMIT ?",
        (MAX_ROWS,)
    ).fetchall()
    conn.close()

    now = utc_now()
    window_start = now - timedelta(minutes=WINDOW_MIN)

    # Filter by time window when possible; if parsing fails for a row, keep it (but it won't dominate much).
    windowed = []
    for ts, host, prog, pid, msg in rows:
        dt = parse_ts(ts)
        if dt is None:
            windowed.append((ts, host, (prog or "").strip(), pid, msg or ""))
            continue
        # dt may be offset-aware; compare in UTC
        try:
            dt_utc = dt.astimezone(timezone.utc)
        except Exception:
            dt_utc = None
        if dt_utc is None or dt_utc >= window_start:
            windowed.append((ts, host, (prog or "").strip(), pid, msg or ""))

    # If the router clock is weird and we got nothing, fall back to the most recent chunk.
    if len(windowed) < 5:
        windowed = [(ts, host, (prog or "").strip(), pid, msg or "") for ts, host, prog, pid, msg in rows[:3000]]

    counts = {}
    alerts = []
    ignored_expected = 0
    ssh_other_ip = 0
    ssh_fail = 0

    nonexpected_events = []
    for ts, host, prog, pid, msg in windowed:
        if prog == "dropbear":
            m = DROPBEAR_CHILD.search(msg)
            if m and m.group("srcip") != NUC_IP:
                ssh_other_ip += 1
                alerts.append({"severity":"high","kind":"ssh_connection_not_from_nuc","src_ip":m.group("srcip"),"msg":msg})
            if DROPBEAR_FAIL.search(msg):
                ssh_fail += 1
                alerts.append({"severity":"high","kind":"ssh_auth_failure","msg":msg})

        if is_expected_nuc_dropbear(prog, msg):
            ignored_expected += 1
        else:
            counts[prog] = counts.get(prog, 0) + 1
            nonexpected_events.append((ts, host, prog, msg))

    top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:12]

    # recent_sample should be *useful* → show non-expected events first
    sample = []
    for ts, host, prog, msg in nonexpected_events[:25]:
        sample.append({"ts": ts, "host": host, "program": prog, "msg": msg})

    if not sample:
        sample = [{
            "ts": utc_now_iso(),
            "host": "netguard",
            "program": "netguard-router-syslog",
            "msg": f"No non-expected router syslog events in the last ~{WINDOW_MIN} minutes (expected NUC SSH noise suppressed)."
        }]

    out = {
        "generated_at": utc_now_iso(),
        "ok": True,
        "error": "",
        "window_minutes_hint": WINDOW_MIN,
        "summary": {
            "rows_considered": len(windowed),
            "ignored_expected_dropbear_from_nuc": ignored_expected,
            "ssh_connections_not_from_nuc": ssh_other_ip,
            "ssh_auth_failures": ssh_fail,
            "top_programs_excluding_expected_ssh": [{"program": k, "count": v} for k, v in top],
            "recent_sample": sample[:20],
        },
        "alerts": alerts[:50],
    }
    OUTJSON.write_text(json.dumps(out, indent=2))

def main():
    try:
        n = ingest()
        summarize()
        print(json.dumps({"ok": True, "ingested": n, "out": str(OUTJSON)}))
    except Exception as e:
        OUTJSON.write_text(json.dumps({
            "generated_at": utc_now_iso(),
            "ok": False,
            "error": str(e),
            "alerts": []
        }, indent=2))
        print(json.dumps({"ok": False, "error": str(e)}))

if __name__ == "__main__":
    main()
