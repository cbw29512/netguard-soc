"""Device inventory and health normalization for NetGuard."""

from typing import Any

from .data_sources import VERSION, read_runtime_json


def device_inventory() -> dict[str, Any]:
    """Build a normalized device list from local router telemetry."""
    telemetry = read_runtime_json(
        "/var/lib/netguard/router_telemetry.json",
        {},
    )
    if not telemetry.get("ok"):
        raise RuntimeError("Telemetry is unavailable")

    findings = read_runtime_json(
        "/var/lib/netguard/router_findings.json",
        {},
    )
    inventory = read_runtime_json(
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
    """Return bounded system-health fields for the dashboard."""
    telemetry = read_runtime_json(
        "/var/lib/netguard/router_telemetry.json",
        {},
    )
    findings = read_runtime_json(
        "/var/lib/netguard/router_findings.json",
        {},
    )
    health = read_runtime_json("/var/lib/netguard/health.json", {})
    ai_state = read_runtime_json(
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
    """Return the current normalized finding collection."""
    return read_runtime_json(
        "/var/lib/netguard/router_findings.json",
        {},
    )
