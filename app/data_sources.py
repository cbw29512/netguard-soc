"""Shared readers for NetGuard runtime files."""

import logging
import pathlib
import sys
from typing import Any

sys.path.insert(0, "/opt/netguard/sensors/lib")
from safe_json import read_json_safe  # noqa: E402

logger = logging.getLogger("netguard.data")
VERSION = "v2.1.0-secure"


def read_runtime_json(path: str, default: Any) -> Any:
    """Read JSON through NetGuard's corruption-safe helper."""
    return read_json_safe(path, default)


def read_recent_lines(path: str, limit: int, fallback: str) -> list[str]:
    """Read a bounded log tail without returning filesystem errors to clients."""
    try:
        return pathlib.Path(path).read_text().splitlines()[-limit:]
    except OSError:
        logger.exception("Failed to read runtime text file: %s", path)
        return [fallback]
