#!/usr/bin/env python3
"""Upgrade an existing native gateway; keep credentials on the hosting machine."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

UNITS = ["cliproxyapi-tailnet.socket", "cliproxyapi-tailnet.service", "cliproxyapi.service"]
INSTALL = Path("/opt/cliproxyapi")
DATA = Path("/var/lib/cliproxyapi")
BACKUPS = Path("/var/backups/cliproxyapi")
BACKUP_KEY = Path("/root/.config/cliproxyapi-backups/key")
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def run(*args):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def keys_from(path):
    keys = {}
    for line in path.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, raw = line.removeprefix("export ").split("=", 1)
            parts = shlex.split(raw)
            if parts:
                keys[key.strip()] = parts[0]
    return keys


def request(base, path, key=None):
    headers = {"Authorization": "Bearer " + key} if key else {}
    req = urllib.request.Request(base + path, headers=headers)
    try:
        with HTTP.open(req, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def snapshot(base, keys):
    status, body = request(base, "/v8/management/routing/sessions", keys["CLIPROXY_MANAGEMENT_KEY"])
    if status != 200:
        raise RuntimeError("management snapshot unavailable")
    value = json.loads(body)
    if value.get("enabled") is not True or value.get("state_error"):
        raise RuntimeError("session ownership is unavailable")
    return value


def verify(base, keys, before=None, require_upgrade=False):
    current = snapshot(base, keys)
    if require_upgrade and any("quota_stopped" not in a for a in current["accounts"]):
        raise RuntimeError("new quota policy is not running")
    if before:
        rows = {s["id"]: s for s in current["sessions"]}
        for old in before["sessions"]:
            # The upgrade normally lasts seconds; expired idle sessions are omitted.
            from datetime import datetime, timezone
            if datetime.fromisoformat(old["expires_at"].replace("Z", "+00:00")) <= datetime.now(timezone.utc):
                continue
            new = rows.get(old["id"])
            if new is None or new["generation"] < old["generation"]:
                raise RuntimeError("an existing session binding was lost")
            if new["generation"] == old["generation"] and new["auth_id"] != old["auth_id"]:
                raise RuntimeError("session ownership changed without a generation")
    for path in ("/v8/management/routing/sessions", "/v1/models"):
        if request(base, path)[0] != 401:
            raise RuntimeError("API authentication boundary changed")
    if request(base, "/v1/models", keys["CLIPROXY_T3_CODEX_KEY"])[0] != 200:
        raise RuntimeError("authenticated model catalog unavailable")
    if request(base, "/management.html")[0] != 200:
        raise RuntimeError("dashboard unavailable")
    status, body = request(base, "/v8/management/config/observability/logs", keys["CLIPROXY_MANAGEMENT_KEY"])
    logs = json.loads(body) if status == 200 else {}
    if logs.get("request-log") is not True or not 0 < logs.get("logs-max-total-size-mb", 0) <= 512:
        raise RuntimeError("bounded request logging is not enabled")
    print("PASS authenticated API, dashboard, session ownership and bounded request logging")
    print("Sessions:", len(current["sessions"]), "Accounts:", len(current["accounts"]))


def encrypt_backup(archive):
    BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(BACKUPS, 0o700)
    BACKUP_KEY.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not BACKUP_KEY.exists():
        with BACKUP_KEY.open("xb") as output:
            os.chmod(BACKUP_KEY, 0o600)
            output.write(os.urandom(48).hex().encode())
    os.chmod(BACKUP_KEY, 0o600)
    # Backup state and credentials as one stopped-process snapshot. Plaintext is
    # streamed directly into encryption; it never becomes a temporary archive.
    with archive.open("xb") as output:
        os.chmod(archive, 0o600)
        tar = subprocess.Popen(["tar", "-C", "/", "-czf", "-", "opt/cliproxyapi", "var/lib/cliproxyapi"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            encryption = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-salt", "-pbkdf2", "-iter", "200000", "-pass", "file:" + str(BACKUP_KEY)], stdin=tar.stdout, stdout=output, stderr=subprocess.PIPE)
            tar.stdout.close()
            _, _ = tar.communicate()
            if encryption.returncode or tar.returncode:
                raise RuntimeError("encrypted backup failed")
        finally:
            if tar.poll() is None:
                tar.terminate()
                tar.wait()


def restore_artifacts(archive):
    # Preserve the latest credentials and pins. Both releases use state version 1;
    # the older binary ignores the additive quota_stops field on rollback.
    decryption = subprocess.Popen(["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-pass", "file:" + str(BACKUP_KEY), "-in", str(archive)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        extraction = subprocess.run(["tar", "-C", "/", "-xzf", "-", "opt/cliproxyapi"], stdin=decryption.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        decryption.stdout.close()
        _, _ = decryption.communicate()
        if extraction.returncode or decryption.returncode:
            raise RuntimeError("artifact rollback failed")
    finally:
        if decryption.poll() is None:
            decryption.terminate()
            decryption.wait()


LEGACY_STOP_WINDOWS = {"confirmed", "anthropic-ratelimit-unified-5h-utilization", "anthropic-ratelimit-unified-7d-utilization", "x-codex-primary-used-percent", "x-codex-secondary-used-percent"}


def legacy_compatible_quota_stops(data=None):
    # Releases before configurable reserves fail closed on any quota stop above 1%
    # remaining. Stops are re-derived from fresh observations, so dropping the ones
    # an older binary cannot load keeps pins and avoids a routing outage on rollback.
    for state in (data or DATA).rglob(".session-affinity.state"):
        document = json.loads(state.read_text())
        stops = document.get("quota_stops") or {}
        changed = False
        for account in list(stops):
            windows = stops[account] or {}
            for name in list(windows):
                stop = windows[name] or {}
                remaining = stop.get("remaining_percent", 0)
                observed = stop.get("observed_at", "")
                if name not in LEGACY_STOP_WINDOWS or not stop.get("reason") or not observed or observed.startswith("0001-") or not 0 <= remaining <= 1:
                    del windows[name]
                    changed = True
            if not windows:
                del stops[account]
                changed = True
        if changed:
            info = state.stat()
            fd, temporary = tempfile.mkstemp(prefix=".routing-", dir=state.parent)
            try:
                with os.fdopen(fd, "w") as output:
                    json.dump(document, output, separators=(",", ":"))
                    output.flush()
                    os.fsync(output.fileno())
                os.chmod(temporary, info.st_mode & 0o777)
                if os.geteuid() == 0:
                    os.chown(temporary, info.st_uid, info.st_gid)
                os.replace(temporary, state)
            finally:
                Path(temporary).unlink(missing_ok=True)
            print("Removed quota stops the restored release cannot load:", state, flush=True)


def install_atomic(source, target, mode):
    fd, temporary = tempfile.mkstemp(prefix=".upgrade-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as output, source.open("rb") as input_file:
            shutil.copyfileobj(input_file, output)
            os.fchmod(output.fileno(), mode)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--base", default="http://127.0.0.1:18317")
    parser.add_argument("--rollback", type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run through sudo in your terminal")
    os.umask(0o077)
    keys = keys_from(DATA / "client-keys.env")
    bundle = args.bundle.resolve()
    if not args.rollback:
        manifest = json.loads((bundle / "manifest.json").read_text())
        required = {"cli-proxy-api", "management.html", "SOURCE_REVISIONS.txt"}
        if not required.issubset(manifest):
            raise RuntimeError("incomplete bundle manifest")
        for name, digest in manifest.items():
            if Path(name).name != name or hashlib.sha256((bundle / name).read_bytes()).hexdigest() != digest:
                raise RuntimeError("bundle checksum validation failed")
        print("PASS bundle checksums")
    before = snapshot(args.base, keys)
    active = [unit for unit in UNITS if subprocess.run(["systemctl", "is-active", "--quiet", unit]).returncode == 0]
    if "cliproxyapi.service" not in active:
        raise RuntimeError("gateway is not active; inspect it before upgrading")
    print("Stopping gateway and ingress; active connections will reconnect.", flush=True)
    run("systemctl", "stop", *UNITS)
    archive = args.rollback or BACKUPS / (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-pre-upgrade.tar.gz.enc")
    installed = False
    try:
        if args.rollback:
            restore_artifacts(archive)
            legacy_compatible_quota_stops()
        else:
            encrypt_backup(archive)
            print("Encrypted backup:", archive, flush=True)
            installed = True
            install_atomic(bundle / "cli-proxy-api", INSTALL / "cli-proxy-api", 0o755)
            install_atomic(bundle / "management.html", INSTALL / "static/management.html", 0o644)
            install_atomic(bundle / "SOURCE_REVISIONS.txt", INSTALL / "SOURCE_REVISIONS.txt", 0o644)
        run("systemctl", "start", "cliproxyapi.service")
        deadline = time.monotonic() + 30
        while True:
            try:
                verify(args.base, keys, before, require_upgrade=not args.rollback)
                break
            except (RuntimeError, urllib.error.URLError, OSError):
                if time.monotonic() >= deadline:
                    raise RuntimeError("post-upgrade verification failed") from None
                time.sleep(0.5)
        ingress = [unit for unit in active if unit != "cliproxyapi.service"]
        if ingress:
            run("systemctl", "start", *ingress)
        print("PASS native gateway upgrade; ingress restored" if not args.rollback else "PASS artifact rollback; latest credentials and pins retained")
        if not args.rollback:
            print("Rollback: sudo python3", bundle / "upgrade-native.py", bundle, "--rollback", archive)
    except Exception:
        run("systemctl", "stop", *UNITS)
        if installed:
            restore_artifacts(archive)
            legacy_compatible_quota_stops()
        run("systemctl", "start", *active)
        print("Previous service restored; inspect the failed upgrade before retrying.", file=sys.stderr)
        raise


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Never print command stderr, provider response bodies or configuration.
        print("Upgrade failed:", type(error).__name__, str(error), file=sys.stderr)
        sys.exit(1)
