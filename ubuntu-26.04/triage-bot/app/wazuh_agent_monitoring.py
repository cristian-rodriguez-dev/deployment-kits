
"""Read-only Wazuh agent monitoring enrichment.

Advisory only. No raw documents persisted, no AI input, no triage changes.
"""

from __future__ import annotations

import base64
import json
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from app.wazuh_indexer import (
    AGENT_RE, USERNAME_RE, URL, PASSWORD_FILE, CA_FILE,
    TIMEOUT, _NoRedirect,
)

VERSION = "wazuh-agent-monitoring-v1"
MAX_BYTES = 16_384
MAX_AGE_SECONDS = 1200
FUTURE_SKEW_SECONDS = 120
ALLOWED_STATES = frozenset({
    "active", "disconnected", "never_connected", "pending"
})


def _base():
    return {
        "version": VERSION,
        "status": "unavailable",
        "source": "wazuh_indexer_monitoring",
        "changes_triage": False,
        "raw_documents_stored": False,
        "sent_to_ai": False,
    }


def _parse_time(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("Invalid timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timezone required")
    return int(parsed.timestamp())


def _query(agent_id):
    return {
        "size": 1,
        "track_total_hits": False,
        "timeout": "2s",
        "_source": [
            "id", "status", "timestamp", "lastKeepAlive",
            "os.name", "os.version", "version",
            "group_config_status"
        ],
        "query": {"term": {"id": agent_id}},
        "sort": [{"timestamp": {"order": "desc"}}],
    }


def _interpret(payload, agent_id, now):
    base = _base()

    if not isinstance(payload, dict) or payload.get("timed_out") is not False:
        return base

    shards = payload.get("_shards")
    if (not isinstance(shards, dict)
            or type(shards.get("failed")) is not int
            or shards["failed"] != 0
            or type(shards.get("successful")) is not int
            or shards["successful"] < 1):
        return base

    hits = payload.get("hits")
    if not isinstance(hits, dict) or not isinstance(hits.get("hits"), list):
        return base

    rows = hits["hits"]
    if not rows:
        return {**base, "status": "no_data"}

    if len(rows) != 1 or not isinstance(rows[0], dict):
        return base

    doc = rows[0].get("_source")
    if not isinstance(doc, dict) or doc.get("id") != agent_id:
        return base

    try:
        recorded = _parse_time(doc.get("timestamp"))
        keepalive = _parse_time(doc.get("lastKeepAlive"))
    except (ValueError, TypeError, OverflowError):
        return base

    recorded_age = now - recorded
    keepalive_age = now - keepalive

    if (recorded_age < -FUTURE_SKEW_SECONDS
            or keepalive_age < -FUTURE_SKEW_SECONDS
            or keepalive > recorded + FUTURE_SKEW_SECONDS):
        return base

    state = doc.get("status")
    if state not in ALLOWED_STATES:
        return base

    os_info = doc.get("os")
    if not isinstance(os_info, dict):
        os_info = {}

    def safe_string(value, limit=64):
        if not isinstance(value, str) or len(value) > limit:
            return ""
        if not all(c.isalnum() or c in " ._+-()" for c in value):
            return ""
        return value

    stale = (
        recorded_age > MAX_AGE_SECONDS
        or keepalive_age > MAX_AGE_SECONDS
    )

    return {
        **base,
        "status": "stale" if stale else "ok",
        "agent_id": agent_id,
        "reported_status": state,
        "last_keepalive_age_seconds": max(0, keepalive_age),
        "record_age_seconds": max(0, recorded_age),
        "freshness_threshold_seconds": MAX_AGE_SECONDS,
        "os_name": safe_string(os_info.get("name")),
        "os_version": safe_string(os_info.get("version")),
        "wazuh_version": safe_string(doc.get("version")),
        "configuration_synced": doc.get("group_config_status") == "synced",
        "agent_live_status_confirmed": False,
    }


def collect(agent, asset, *, username,
            password_file=PASSWORD_FILE, ca_file=CA_FILE,
            url=URL, now=None, opener=None):
    base = _base()

    if not isinstance(agent, dict) or not isinstance(asset, dict):
        return base

    agent_id = agent.get("id")
    if (not isinstance(agent_id, str)
            or not AGENT_RE.fullmatch(agent_id)
            or asset.get("agent_id") != agent_id):
        return base

    if now is None:
        now = int(time.time())

    if type(now) is not int or not 1_600_000_000 <= now <= 4_000_000_000:
        return base

    if (url != URL
            or not isinstance(username, str)
            or not USERNAME_RE.fullmatch(username)
            or not isinstance(password_file, str)
            or not Path(password_file).is_absolute()
            or not isinstance(ca_file, str)
            or not Path(ca_file).is_absolute()):
        return base

    try:
        password = Path(password_file).read_text(encoding="utf-8")
        if not 12 <= len(password) <= 512 or "\n" in password or "\r" in password:
            return base

        context = ssl.create_default_context(cafile=ca_file)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        credentials = base64.b64encode(
            f"{username}:{password}".encode()
        ).decode("ascii")

        request = urllib.request.Request(
            URL + "/wazuh-monitoring-*/_search",
            data=json.dumps(_query(agent_id)).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Basic " + credentials,
            },
            method="POST",
        )
        credentials = ""

        client = opener or urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            urllib.request.ProxyHandler({}),
            _NoRedirect(),
        )

        with client.open(request, timeout=TIMEOUT) as response:
            if response.status != 200:
                return base
            raw = response.read(MAX_BYTES + 1)

        if len(raw) > MAX_BYTES:
            return base

        return _interpret(json.loads(raw), agent_id, now)

    except (OSError, ValueError, TypeError, KeyError,
            UnicodeError, ssl.SSLError,
            urllib.error.URLError, json.JSONDecodeError):
        return base
