"""Agent self-update.

The server publishes a manifest (`GET /api/v1/update/manifest`) listing the
latest agent version and one artifact per platform key, e.g.

    linux-x86_64, linux-arm64, darwin-arm64, darwin-x86_64,
    windows-x86_64, windows-arm64

The agent downloads the artifact for its platform, verifies the SHA-256 from
the manifest, swaps the executable, and exits(0) so the service manager
(systemd / launchd / Windows task) restarts it on the new version.

Self-replacement only happens for frozen (PyInstaller) builds; source runs
report that a manual update is needed instead.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import ssl
import sys
import tempfile
import urllib.request


class UpdateError(Exception):
    pass


def parse_version(v: str) -> tuple[int, ...]:
    """'1.10.2' -> (1, 10, 2); tolerant of suffixes like '1.1.0-rc1'."""
    parts = []
    for chunk in str(v or "0").split("-")[0].split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts) or (0,)


def newer(candidate: str, current: str) -> bool:
    a, b = parse_version(candidate), parse_version(current)
    n = max(len(a), len(b))
    a += (0,) * (n - len(a))
    b += (0,) * (n - len(b))
    return a > b


def platform_key() -> str:
    os_name = platform.system().lower()          # linux / darwin / windows
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64", "x64"):
        arch = "x86_64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    elif machine.startswith("i") and machine.endswith("86"):
        arch = "x86"
    else:
        arch = machine or "unknown"
    return f"{os_name}-{arch}"


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def fetch_manifest(server_url: str, ssl_ctx: ssl.SSLContext | None = None,
                   timeout: float = 15.0) -> dict:
    url = server_url.rstrip("/") + "/api/v1/update/manifest"
    req = urllib.request.Request(url, headers={"User-Agent": "OpenEyes-Agent"})
    with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
        return json.loads(resp.read().decode())


def pick_asset(manifest: dict, key: str | None = None) -> dict | None:
    assets = manifest.get("assets") or {}
    return assets.get(key or platform_key())


def download_asset(server_url: str, asset: dict,
                   ssl_ctx: ssl.SSLContext | None = None,
                   timeout: float = 120.0) -> str:
    """Download to a temp file, verify SHA-256; return the temp path."""
    url = server_url.rstrip("/") + asset["url"]
    req = urllib.request.Request(url, headers={"User-Agent": "OpenEyes-Agent"})
    fd, tmp = tempfile.mkstemp(prefix="openeyes-update-")
    h = hashlib.sha256()
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=ssl_ctx) as resp, \
                os.fdopen(fd, "wb") as out:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                h.update(chunk)
                out.write(chunk)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if h.hexdigest() != asset.get("sha256", ""):
        os.unlink(tmp)
        raise UpdateError("SHA-256 mismatch — refusing to install update")
    return tmp


def swap_executable(new_path: str) -> None:
    """Replace the running executable; service manager restarts the agent."""
    if not is_frozen():
        raise UpdateError(
            "running from source — self-replace is only supported for "
            "packaged (PyInstaller) agent builds")
    current = os.path.abspath(sys.executable)
    old = current + ".old"
    try:
        if os.path.exists(old):
            os.unlink(old)
        # Renaming works even while the binary is running (incl. Windows).
        os.replace(current, old)
        shutil.move(new_path, current)
        os.chmod(current, 0o755)
    except OSError as e:
        # try to roll back
        if not os.path.exists(current) and os.path.exists(old):
            try:
                os.replace(old, current)
            except OSError:
                pass
        raise UpdateError(f"failed to replace executable: {e}")


def check_and_apply(server_url: str, current_version: str,
                    ssl_ctx: ssl.SSLContext | None = None,
                    log=print) -> bool:
    """Full update cycle. Returns True if an update was installed."""
    try:
        manifest = fetch_manifest(server_url, ssl_ctx)
    except Exception as e:
        log(f"Update check failed: {e}")
        return False
    latest = manifest.get("agent_version")
    if not latest or not newer(latest, current_version):
        return False
    asset = pick_asset(manifest)
    if not asset:
        log(f"Update {latest} available but no artifact for "
            f"{platform_key()} — skipping")
        return False
    log(f"Update available: {current_version} -> {latest} "
        f"({asset.get('size', '?')} bytes)")
    try:
        tmp = download_asset(server_url, asset, ssl_ctx)
        swap_executable(tmp)
    except (UpdateError, OSError) as e:
        log(f"Update NOT applied: {e}")
        return False
    log(f"Update to {latest} installed — restarting into new version")
    return True
