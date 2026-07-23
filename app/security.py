"""Authentication and host-validation settings for NetGuard."""

import logging
import os
import secrets
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

logger = logging.getLogger("netguard.security")
security = HTTPBasic(auto_error=False)


def allowed_hosts() -> list[str]:
    """Return deployment-approved HTTP Host header values."""
    raw_hosts = os.getenv(
        "NETGUARD_ALLOWED_HOSTS",
        "localhost,127.0.0.1,[::1]",
    )
    return [host.strip() for host in raw_hosts.split(",") if host.strip()]


def require_auth(
    credentials: Optional[HTTPBasicCredentials] = Depends(security),
) -> str:
    """Validate Basic credentials without leaking which field was wrong."""
    expected_username = os.getenv("NETGUARD_USERNAME")
    expected_password = os.getenv("NETGUARD_PASSWORD")
    if not expected_username or not expected_password:
        logger.critical("NetGuard credentials are not configured")
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
