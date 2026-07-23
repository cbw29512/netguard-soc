"""Authenticated HTML endpoints for NetGuard."""

import pathlib

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()
STATIC_ROOT = pathlib.Path("/opt/netguard/static")


@router.get("/", response_class=HTMLResponse)
def dashboard():
    return (STATIC_ROOT / "ng_live.html").read_text()


@router.get("/v2", response_class=HTMLResponse)
def dashboard_v2():
    return (STATIC_ROOT / "ng_unified.html").read_text()
