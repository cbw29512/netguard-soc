"""Read and normalize NetGuard runtime data without exposing raw errors."""

import csv
import io
import logging
import pathlib
import sys
from typing import Any

import requests

sys.path.insert(0, "/opt/netguard/sensors/lib")
from safe_json import read_json_safe  # noqa: E402

logger = logging.getLogger("netguard.data")
VERSION = "v2.1.0-secure"


def traffic_state() -> dict[str, Any]:
    """Query local InfluxDB and return normalized upload/download counters."""
    try:
        token = pathlib.Path(
            "/opt/netguard/secrets/influx_admin.token"
        ).read_text().strip()
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

        totals: dict[str, dict[str, int]] = {}
        for row in csv.reader(io.StringIO(response.text)):
            if len(row) < 7 or row[1].strip() != "_result":
                continue
            ip_address = row[6].strip()
            field = row[5].strip()
            value = int(float(row[4])) if row[4].strip() else 0
            totals.setdefault(ip_address, {"up": 0, "down": 0})
            if field in {"up", "down"}:
                totals[ip_address][field] += value

        cards = [
            {"ip": ip_address, **values}
            for ip_address, values in totals.items()
        ]
        return {
            "ip_cards": sorted(
                cards,
                key=lambda item: item["up"] + item["down"],
                reverse=True,
            )
        }
    except (OSError, ValueError, requests.RequestException) as exc:
        logger.exception("Failed to load traffic state")
        raise RuntimeError("Network traffic data is unavailable") from exc


def wifi_scan() -> dict[str, Any]:
    return read_json_safe(
        "/var/lib/netguard/wifi_scan.json",
        {"networks": []},
    )


def ai_thoughts() -> dict[str, list[str]]:
    try:
        lines = pathlib.Path(
            "/var/lib/netguard/ai_thoughts.log"
        ).read_text().splitlines()
        return {"lines": lines[-15:]}
    except OSError:
        logger.exception("Failed to read AI activity log")
        return {"lines": ["AI Security Guard Active"]}


def device_inventory() -> dict[str, Any]:
    telemetry = read_json_safe(
        "/var/lib/netguard/router_telemetry.json",
        {},
    )
    if not telemetry.get("ok"):
        raise RuntimeError("Telemetry is unavailable")

    findings = read_json_safe(
        "/var/lib/netguard/router_findings.json",
        {},
    )
    inventory = read_json_safe(
        "/var/lib/netguard/router_inventory.json",
        {},
    )
    clients = telemetry.get("clients", {}) or {}
    reservations = inventory.get("reservations", []) or []
    arp_entries = clients.get("arp", []) or []

    devices = []
    for lease in clients.get("dhcp_leases", []) or []:
        mac_address = str(lease.get("mac", "")).lower()
        if not mac_address:
            continue
        ip_address = str(lease.get("ip", ""))
        reserved = next(
            (
                item
                for item in reservations
                if str(item.get("mac", "")).lower() == mac_address
            ),
            None,
        )
        alerts = [
            alert
            for alert in findings.get("alerts", []) or []
            if mac_address in str(alert) or ip_address in str(alert)
        ]
        reachable = any(
            str(item.get("mac", "")).lower() == mac_address
            for item in arp_entries
        )
        devices.append(
            {
                "mac": mac_address,
                "ip": ip_address,
                "hostname": lease.get("hostname", "Unknown"),
                "known": reserved is not None,
                "reserved_name": reserved.get("name", "") if reserved else "",
                "reachable": reachable,
                "alerts": alerts,
                "alert_count": len(alerts),
            }
        )
    return {"devices": devices, "count": len(devices)}


def status_summary() -> dict[str, Any]:
    telemetry = read_json_safe(
        "/var/lib/netguard/router_telemetry.json",
        {},
    )
    findings = read_json_safe(
        "/var/lib/netguard/router_findings.json",
        {},
    )
    health = read_json_safe("/var/lib/netguard/health.json", {})
    ai_state = read_json_safe(
        "/var/lib/netguard/ai_guard_state.json",
        {},
    )
    return {
        "version": VERSION,
        "telemetry_ok": telemetry.get("ok", False),
        "active_alerts": len(findings.get("alerts", [])),
        "health_status": health.get("status", "unknown"),
        "ai_active": bool(ai_state.get("thoughts", [])),
        "last_update": telemetry.get("generated_at", "unknown"),
    }


def findings() -> dict[str, Any]:
    return read_json_safe(
        "/var/lib/netguard/router_findings.json",
        {},
    )
