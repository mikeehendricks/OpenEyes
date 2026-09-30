"""WAN-IP geolocation with SQLite caching.

Uses the free ip-api.com service (no key required) and degrades gracefully:
private IPs are skipped, network failures return the stale cache (or None),
and a per-process lock prevents lookup storms.
"""
from __future__ import annotations

import ipaddress
import json
import threading
import time
import urllib.request

CACHE_DAYS = 30
LOOKUP_TIMEOUT = 4.0
API_URL = "http://ip-api.com/json/{ip}?fields=status,lat,lon,city,country"

_lock = threading.Lock()
_inflight: set[str] = set()


def is_private(ip: str | None) -> bool:
    if not ip:
        return True
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return True
    return (a.is_private or a.is_loopback or a.is_link_local
            or a.is_reserved or a.is_multicast or a.is_unspecified)


def lookup(ip: str | None, db) -> dict | None:
    """Return {"lat","lon","city","country"} for a WAN IP, else None."""
    if is_private(ip):
        return None
    cached = db.get_geoip(ip)
    if cached and (time.time() - cached["ts"]) < CACHE_DAYS * 86400:
        return _fmt(cached)

    with _lock:
        if ip in _inflight:
            return _fmt(cached) if cached else None
        _inflight.add(ip)
    try:
        req = urllib.request.Request(API_URL.format(ip=ip),
                                     headers={"User-Agent": "OpenEyes/1.1"})
        with urllib.request.urlopen(req, timeout=LOOKUP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            db.set_geoip(ip, lat=float(data["lat"]), lon=float(data["lon"]),
                         city=data.get("city"), country=data.get("country"))
            return {"lat": float(data["lat"]), "lon": float(data["lon"]),
                    "city": data.get("city"), "country": data.get("country")}
        return _fmt(cached) if cached else None
    except Exception:
        # offline / rate-limited: stale cache beats nothing
        return _fmt(cached) if cached else None
    finally:
        with _lock:
            _inflight.discard(ip)


def _fmt(row: dict | None) -> dict | None:
    if not row or row.get("lat") is None:
        return None
    return {"lat": row["lat"], "lon": row["lon"],
            "city": row.get("city"), "country": row.get("country")}
