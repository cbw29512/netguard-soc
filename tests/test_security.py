import pytest
from fastapi import HTTPException
from fastapi.security import HTTPBasicCredentials

from app.security import allowed_hosts, require_auth


def test_authentication_fails_closed_without_configuration(monkeypatch) -> None:
    monkeypatch.delenv("NETGUARD_USERNAME", raising=False)
    monkeypatch.delenv("NETGUARD_PASSWORD", raising=False)

    with pytest.raises(HTTPException) as error:
        require_auth(None)

    assert error.value.status_code == 503


def test_authentication_rejects_invalid_credentials(monkeypatch) -> None:
    monkeypatch.setenv("NETGUARD_USERNAME", "operator")
    monkeypatch.setenv("NETGUARD_PASSWORD", "correct-password")
    credentials = HTTPBasicCredentials(
        username="operator",
        password="wrong-password",
    )

    with pytest.raises(HTTPException) as error:
        require_auth(credentials)

    assert error.value.status_code == 401


def test_authentication_accepts_exact_credentials(monkeypatch) -> None:
    monkeypatch.setenv("NETGUARD_USERNAME", "operator")
    monkeypatch.setenv("NETGUARD_PASSWORD", "correct-password")
    credentials = HTTPBasicCredentials(
        username="operator",
        password="correct-password",
    )

    assert require_auth(credentials) == "operator"


def test_allowed_hosts_are_explicit(monkeypatch) -> None:
    monkeypatch.setenv(
        "NETGUARD_ALLOWED_HOSTS",
        "localhost,127.0.0.1,netguard.internal",
    )

    assert allowed_hosts() == [
        "localhost",
        "127.0.0.1",
        "netguard.internal",
    ]
