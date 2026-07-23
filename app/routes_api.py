"""Authenticated JSON endpoints for the NetGuard dashboard."""

from fastapi import APIRouter, HTTPException

from .data_sources import read_recent_lines, read_runtime_json
from .inventory_sources import device_inventory, findings, status_summary
from .traffic_sources import traffic_state

router = APIRouter(prefix="/api")


@router.get("/state")
def get_state():
    try:
        return traffic_state()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get("/wifi_scan")
def get_wifi():
    return read_runtime_json(
        "/var/lib/netguard/wifi_scan.json",
        {"networks": []},
    )


@router.get("/ai_thoughts")
def get_ai_thoughts():
    return {
        "lines": read_recent_lines(
            "/var/lib/netguard/ai_thoughts.log",
            limit=15,
            fallback="AI Security Guard Active",
        )
    }


@router.get("/devices")
def get_devices():
    try:
        return device_inventory()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get("/status")
def get_status():
    return status_summary()


@router.get("/findings")
def get_findings():
    return findings()
