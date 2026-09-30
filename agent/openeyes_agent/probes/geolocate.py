"""Resolve the agent device's actual location from its egress (WAN) IP.

The device itself asks a public GeoIP service where *it* is on the internet,
so the server displays the real place of the machine regardless of NAT /
proxy topologies on the server side. Fully fault tolerant: any failure
returns None and the agent keeps monitoring.
"""
from __future__ import annotations

import json
import urllib.request

GEO_URL = ("http://ip-api.com/json/"
           "?fields=status,city,regionName,country,countryCode,lat,lon")
TIMEOUT = 5.0


def own_location(timeout: float = TIMEOUT) -> dict | None:
    try:
        req = urllib.request.Request(GEO_URL,
                                     headers={"User-Agent": "OpenEyes-Agent"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") != "success":
            return None
        return {
            "lat": float(data["lat"]),
            "lng": float(data["lon"]),
            "city": data.get("city"),
            "region": data.get("regionName"),
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "source": "device",
        }
    except (OSError, ValueError, KeyError, TypeError):
        return None
