"""InfluxDB traffic access for NetGuard."""

import csv
import io
import logging
import pathlib
from typing import Any

import requests

logger = logging.getLogger("netguard.traffic")


def traffic_state() -> dict[str, Any]:
    """Query local InfluxDB and normalize upload/download counters."""
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
