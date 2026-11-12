#!/usr/bin/env python3
"""Poll Loki for selected Traefik access logs; append minimal Wazuh JSONL events.

Standard library only. At-least-once delivery: after a crash, a small number of
lines may be replayed. No Docker socket, Kubernetes credentials, or Wazuh API.
"""
from __future__ import annotations

import argparse
import hashlib
try:
    import fcntl  # Linux production
except ImportError:
    fcntl = None
    import msvcrt  # Windows-only offline tests
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

LOG = logging.getLogger("traefik_wazuh_bridge")
DEFAULT_QUERY = '{app="traefik",namespace="kube-system"} | json'
SENSITIVE_PATH_RE = re.compile(r"(?i)(?:/\.env(?:/|$)|/\.git(?:/|$)|/wp-admin(?:/|$)|/actuator(?:/|$)|/cgi-bin(?:/|$)|/vendor/phpunit(?:/|$))")
HTTP_CODES = {401, 403, 404, 429}


class BridgeError(RuntimeError):
    """A retryable or configuration error requiring attention."""


def load_config(path: str) -> dict:
    cfg = json.loads(Path(path).read_text(encoding="utf-8"))
    required = ("loki_url", "output_path", "state_path")
    if any(not isinstance(cfg.get(name), str) or not cfg[name] for name in required):
        raise BridgeError("Config requires loki_url, output_path and state_path")
    url = urllib.parse.urlsplit(cfg["loki_url"])
    if url.scheme not in {"http", "https"} or not url.netloc or url.username or url.password:
        raise BridgeError("loki_url must be http(s) without embedded credentials")
    cfg.setdefault("query", DEFAULT_QUERY)
    cfg.setdefault("poll_seconds", 15)
    cfg.setdefault("lag_seconds", 10)
    cfg.setdefault("overlap_seconds", 20)
    cfg.setdefault("initial_lookback_seconds", 120)
    cfg.setdefault("window_seconds", 30)
    cfg.setdefault("max_windows_per_poll", 12)
    cfg.setdefault("limit", 1000)
    cfg.setdefault("max_output_bytes", 52428800)
    for field in ("poll_seconds", "lag_seconds", "overlap_seconds", "initial_lookback_seconds", "window_seconds", "max_windows_per_poll", "limit", "max_output_bytes"):
        val = cfg[field]
        if isinstance(val, bool) or not isinstance(val, int) or val <= 0:
            raise BridgeError(f"{field} must be a positive integer")
    if cfg["limit"] > 5000:
        raise BridgeError("limit must be <= 5000")
    if not isinstance(cfg["query"], str) or not cfg["query"].strip():
        raise BridgeError("query must be a non-empty LogQL expression")
    if Path(cfg["output_path"]).parent.resolve() == Path(cfg["state_path"]).parent.resolve():
        raise BridgeError("Separate event and state directories are required")
    return cfg


def event_id(labels: dict, ts: str, line: str) -> str:
    payload = json.dumps(labels, sort_keys=True, separators=(",", ":")) + "\0" + ts + "\0" + line
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def translate(labels: dict, ts: str, raw: str) -> dict | None:
    try:
        event = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(event, dict) or event.get("RequestMethod") is None:
        return None
    path = event.get("RequestPath", "")
    if not isinstance(path, str):
        return None
    # Traefik is configured to remove query parameters, but defensively strip
    # any that appear in unexpected upstream log formats.
    path = path.split("?", 1)[0].split("#", 1)[0][:1024]
    try:
        code = int(event.get("DownstreamStatus", -1))
    except (ValueError, TypeError):
        return None
    if code not in HTTP_CODES and not SENSITIVE_PATH_RE.search(path):
        return None
    client = event.get("ClientHost") or ""
    try:
        client = str(ipaddress.ip_address(str(client)))
    except ValueError:
        client = ""
    method = str(event["RequestMethod"])[:12]
    router = str(event.get("RouterName") or "")[:160]
    return {
        "integration": "traefik_loki",
        "EventId": event_id(labels, ts, raw),
        "LokiTimestampNs": ts,
        "RequestMethod": method,
        "RequestPath": path,
        "DownstreamStatus": code,
        "ClientHost": client,
        "RouterName": router,
        "Cluster": str(labels.get("cluster") or "")[:80],
    }


def fetch_loki(cfg: dict, start_ns: int, end_ns: int) -> list:
    params = urllib.parse.urlencode({
        "query": cfg["query"], "start": str(start_ns), "end": str(end_ns),
        "direction": "forward", "limit": str(cfg["limit"]),
    })
    url = cfg["loki_url"].rstrip("/") + "/loki/api/v1/query_range?" + params
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "traefik-wazuh-bridge/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.load(resp)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise BridgeError(f"Loki query failed: {exc}") from exc
    if data.get("status") != "success" or data.get("data", {}).get("resultType") != "streams":
        raise BridgeError("Unexpected Loki response format")
    rows = []
    for stream in data["data"].get("result", []):
        labels = stream.get("stream", {})
        if labels.get("app") != "traefik" or labels.get("namespace") != "kube-system":
            continue
        for ts, raw in stream.get("values", []):
            t = int(ts)
            if start_ns <= t <= end_ns:
                rows.append((t, labels, raw))
    rows.sort(key=lambda row: (row[0], event_id(row[1], str(row[0]), row[2])))
    if len(rows) >= cfg["limit"]:
        # Never advance the cursor across a potentially truncated Loki result.
        raise BridgeError(f"Loki result reached limit={cfg['limit']}; increase limit or reduce window_seconds")
    return rows


def open_database(state_path: str) -> sqlite3.Connection:
    path = Path(state_path)
    if not path.parent.is_dir() or path.is_symlink():
        raise BridgeError("State directory must exist and state file must not be a symlink")
    db = sqlite3.connect(path)
    db.execute("PRAGMA synchronous=FULL")
    db.execute("CREATE TABLE IF NOT EXISTS seen (id TEXT PRIMARY KEY, ts_ns INTEGER NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    db.commit()
    return db


def output_fd(path: str) -> int:
    parent = Path(path).parent
    if not parent.is_dir() or parent.is_symlink():
        raise BridgeError("Output directory must exist and must not be a symlink")
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o640)
    mode = os.fstat(fd).st_mode
    if not stat.S_ISREG(mode):
        os.close(fd)
        raise BridgeError("Output destination is not a regular file")
    if os.name == "posix" and mode & stat.S_IRWXO:
        os.close(fd)
        raise BridgeError("Output log must not grant permissions to other users")
    return fd


def get_cursor(db: sqlite3.Connection, initial: int) -> int:
    row = db.execute("SELECT value FROM settings WHERE key='cursor_ns'").fetchone()
    return int(row[0]) if row else initial


def cycle(cfg: dict, *, dry_run: bool = False, now_ns: int | None = None) -> tuple[int, int]:
    now = now_ns if now_ns is not None else time.time_ns()
    ready_until = now - cfg["lag_seconds"] * 1_000_000_000
    initial = now - cfg["initial_lookback_seconds"] * 1_000_000_000
    lockfd = None
    if dry_run:
        cursor = initial
        db = None
    else:
        lockpath = Path(cfg["state_path"] + ".lock")
        lockfd = os.open(str(lockpath), os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            if fcntl is not None:
                fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                # Windows offline-test compatibility; Linux uses flock.
                if os.fstat(lockfd).st_size == 0:
                    os.write(lockfd, b"0")
                os.lseek(lockfd, 0, os.SEEK_SET)
                msvcrt.locking(lockfd, msvcrt.LK_NBLCK, 1)
        except BlockingIOError as exc:
            os.close(lockfd)
            raise BridgeError("Another bridge instance holds the state lock") from exc
        db = open_database(cfg["state_path"])
        cursor = get_cursor(db, initial)
    sent = 0
    scanned = 0
    try:
        for _ in range(cfg["max_windows_per_poll"]):
            if cursor >= ready_until:
                break
            start = max(0, cursor - cfg["overlap_seconds"] * 1_000_000_000)
            end = min(cursor + cfg["window_seconds"] * 1_000_000_000, ready_until)
            rows = fetch_loki(cfg, start, end)
            translated = []
            for ts, labels, raw in rows:
                item = translate(labels, str(ts), raw)
                if item is not None:
                    translated.append((ts, item))
            if dry_run:
                scanned += len(rows)
                sent += len(translated)
            else:
                fd = output_fd(cfg["output_path"])
                try:
                    for ts, item in translated:
                        item_id = item["EventId"]
                        if db.execute("SELECT 1 FROM seen WHERE id=?", (item_id,)).fetchone():
                            continue
                        line = (json.dumps(item, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
                        if os.fstat(fd).st_size + len(line) > cfg["max_output_bytes"]:
                            raise BridgeError("Output exceeds max_output_bytes; rotate and preserve files before retrying")
                        n = os.write(fd, line)
                        if n != len(line):
                            raise BridgeError("Short append to output file")
                        os.fsync(fd)
                        db.execute("INSERT INTO seen(id, ts_ns) VALUES (?, ?)", (item_id, ts))
                        db.commit()  # Avoid a second append on regular restarts.
                        sent += 1
                finally:
                    os.close(fd)
                db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES ('cursor_ns', ?)", (str(end),))
                # Keep enough seen IDs to suppress duplicates from the overlap.
                db.execute("DELETE FROM seen WHERE ts_ns < ?", (end - 86400 * 1_000_000_000,))
                db.commit()
                scanned += len(rows)
            cursor = end
    finally:
        if db:
            db.close()
        if lockfd is not None:
            if fcntl is not None:
                fcntl.flock(lockfd, fcntl.LOCK_UN)
            else:
                os.lseek(lockfd, 0, os.SEEK_SET)
                msvcrt.locking(lockfd, msvcrt.LK_UNLCK, 1)
            os.close(lockfd)
    return scanned, sent


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="Query Loki only; never write state or logs")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        cfg = load_config(args.config)
        while True:
            scanned, sent = cycle(cfg, dry_run=args.dry_run)
            LOG.info("scanned=%s selected=%s dry_run=%s", scanned, sent, args.dry_run)
            if args.once or args.dry_run:
                return 0
            time.sleep(cfg["poll_seconds"])
    except (BridgeError, OSError, sqlite3.Error, ValueError) as exc:
        LOG.error("bridge halted safely: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
