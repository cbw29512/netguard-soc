import csv
import io
import logging
import os
import pathlib
import secrets
import sys
from typing import Optional

import requests
from fastapi import APIRouter, Depends, FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

sys.path.insert(0, "/opt/netguard/sensors/lib")
from safe_json import read_json_safe  # noqa: E402

logger = logging.getLogger("netguard.api")
VERSION = "v2.1.0-secure"
security = HTTPBasic(auto_error=False)


def _allowed_hosts() -> list[str]:
    raw_hosts = os.getenv("NETGUARD_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]")
    return [host.strip() for host in raw_hosts.split(",") if host.strip()]


def require_auth(
    credentials: Optional[HTTPBasicCredentials] = Depends(security),
) -> str:
    """Require credentials supplied through deployment-only environment variables."""
    expected_username = os.getenv("NETGUARD_USERNAME")
    expected_password = os.getenv("NETGUARD_PASSWORD")
    if not expected_username or not expected_password:
        logger.critical("NETGUARD_USERNAME and NETGUARD_PASSWORD are not configured")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="NetGuard authentication is not configured.",
        )

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Basic realm=netguard"},
        )

    username_ok = secrets.compare_digest(
        credentials.username.encode("utf-8"),
        expected_username.encode("utf-8"),
    )
    password_ok = secrets.compare_digest(
        credentials.password.encode("utf-8"),
        expected_password.encode("utf-8"),
    )
    if not (username_ok and password_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
            headers={"WWW-Authenticate": "Basic realm=netguard"},
        )
    return credentials.username


app = FastAPI(title="NetGuard SOC", version=VERSION, docs_url=None, redoc_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=_allowed_hosts())
app.mount("/static", StaticFiles(directory="/opt/netguard/static"), name="static")
protected = APIRouter(dependencies=[Depends(require_auth)])


@app.middleware("http")
async def prevent_sensitive_caching(request, call_next):
    response = await call_next(request)
    if request.url.path == "/" or request.url.path == "/v2" or request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
    return response


@protected.get("/api/state")
def get_state():
    try:
        token = pathlib.Path("/opt/netguard/secrets/influx_admin.token").read_text().strip()
        flux = (
            'from(bucket: "network_stats") |> range(start: -10m) '
            '|> filter(fn: (r) => r._measurement == "traffic")'
        )
        response = requests.post(
            "http://127.0.0.1:8086/api/v2/query?org=netguard",
            headers={
                "Authorization": f"Token {token}",
                "Accept": "application/csv",
                "Content-Type": "application/vnd.flux",
            },
            data=flux,
            timeout=5,
        )
        response.raise_for_status()

        data_map: dict[str, dict[str, int]] = {}
        for row in csv.reader(io.StringIO(response.text)):
            if len(row) < 7 or row[1].strip() != "_result":
                continue
            ip = row[6].strip()
            field = row[5].strip()
            value = int(float(row[4])) if row[4].strip() else 0
            data_map.setdefault(ip, {"up": 0, "down": 0})
            if field in {"up", "down"}:
                data_map[ip][field] += value

        cards = [{"ip": ip, **values} for ip, values in data_map.items()]
        return {"ip_cards": sorted(cards, key=lambda item: item["up"] + item["down"], reverse=True)}
    except (OSError, ValueError, requests.RequestException):
        logger.exception("Failed to load network traffic state")
        raise HTTPException(status_code=503, detail="Network traffic data is unavailable.")


@protected.get("/api/wifi_scan")
def get_wifi():
    return read_json_safe("/var/lib/netguard/wifi_scan.json", {"networks": []})


@protected.get("/api/ai_thoughts")
def get_ai_thoughts():
    try:
        lines = pathlib.Path("/var/lib/netguard/ai_thoughts.log").read_text().splitlines()
        return {"lines": lines[-15:]}
    except OSError:
        logger.exception("Failed to read AI activity log")
        return {"lines": ["AI Security Guard Active"]}


@protected.get("/api/devices")
def get_devices():
    telemetry = read_json_safe("/var/lib/netguard/router_telemetry.json", {})
    findings = read_json_safe("/var/lib/netguard/router_findings.json", {})
    inventory = read_json_safe("/var/lib/netguard/router_inventory.json", {})
    if not telemetry.get("ok"):
        raise HTTPException(status_code=503, detail="Telemetry is unavailable.")

    clients = telemetry.get("clients", {}) or {}
    reservations = inventory.get("reservations", []) or []
    arp_entries = clients.get("arp", []) or []
    devices = []
    for lease in clients.get("dhcp_leases", []) or []:
        mac = str(lease.get("mac", "")).lower()
        if not mac:
            continue
        ip = str(lease.get("ip", ""))
        reserved = next((item for item in reservations if str(item.get("mac", "")).lower() == mac), None)
        alerts = [alert for alert in findings.get("alerts", []) or [] if mac in str(alert) or ip in str(alert)]
        reachable = any(str(item.get("mac", "")).lower() == mac for item in arp_entries)
        devices.append({
            "mac": mac,
            "ip": ip,
            "hostname": lease.get("hostname", "Unknown"),
            "known": reserved is not None,
            "reserved_name": reserved.get("name", "") if reserved else "",
            "reachable": reachable,
            "alerts": alerts,
            "alert_count": len(alerts),
        })
    return {"devices": devices, "count": len(devices)}


@protected.get("/api/status")
def api_status():
    telemetry = read_json_safe("/var/lib/netguard/router_telemetry.json", {})
    findings = read_json_safe("/var/lib/netguard/router_findings.json", {})
    health = read_json_safe("/var/lib/netguard/health.json", {})
    ai_state = read_json_safe("/var/lib/netguard/ai_guard_state.json", {})
    return {
        "version": VERSION,
        "telemetry_ok": telemetry.get("ok", False),
        "active_alerts": len(findings.get("alerts", [])),
        "health_status": health.get("status", "unknown"),
        "ai_active": bool(ai_state.get("thoughts", [])),
        "last_update": telemetry.get("generated_at", "unknown"),
    }


@protected.get("/api/findings")
def get_findings():
    return read_json_safe("/var/lib/netguard/router_findings.json", {})


@protected.get("/", response_class=HTMLResponse)
def root():
    return pathlib.Path("/opt/netguard/static/ng_live.html").read_text()


@protected.get("/v2", response_class=HTMLResponse)
def root_v2():
    return pathlib.Path("/opt/netguard/static/ng_unified.html").read_text()


app.include_router(protected)
