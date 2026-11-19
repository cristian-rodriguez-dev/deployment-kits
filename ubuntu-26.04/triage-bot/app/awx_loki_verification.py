"""Pilas Observabilidad / 19D: verificación remota SOLO LECTURA de AWX 19C.

No crea jobs, no cambia AWX/K3s, no accede a DB y no permite remediaciones.
La confianza se obtiene leyendo *dos recursos autenticados* del propio AWX:
- GET /api/v2/jobs/<id>/
- GET /api/v2/jobs/<id>/job_events/

No consumir flags de confianza procedentes de mensajes externos.
"""
from __future__ import annotations

import json
import stat
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from app.remediation_proposal import MAX_OBSERVATION_AGE_SECONDS

JOB_PLAYBOOK = "monitorizacion/playbooks/auditar_loki_k3s_remediacion.yml"
TASK_NAME = "Mostrar solo observacion apta para revision manual"
JOB_HOST = "ansible_server"
DIAGNOSTIC_VERSION = "loki-k3s-awx-diagnostic-v1"
MAX_RESPONSE_BYTES = 1_000_000
MAX_JOB_EVENTS = 200
HTTP_TIMEOUT_SECONDS = 6


class AWXVerificationError(ValueError):
    """Error categorizado. No incluir URLs, tokens, respuesta o detalles de red."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class AWXReadOnlyConfig:
    base_url: str
    token_file: Path
    ca_file: Path | None
    job_template_id: int
    inventory_id: int
    project_id: int


@dataclass(frozen=True)
class VerifiedLokiObservation:
    """Resultado interno verificado, no un certificado ni una autorización."""

    job_id: int
    finished_at_utc: str
    observation: dict[str, Any]


def _utc(value: Any) -> datetime:
    if not isinstance(value, str) or not 1 <= len(value) <= 45:
        raise AWXVerificationError("invalid_timestamp")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AWXVerificationError("invalid_timestamp") from None
    if dt.tzinfo is None:
        raise AWXVerificationError("invalid_timestamp")
    return dt.astimezone(timezone.utc)


def _valid_id(value: Any) -> bool:
    return type(value) is int and 1 <= value <= 2_147_483_647


def _config_base(config: AWXReadOnlyConfig) -> str:
    if not isinstance(config, AWXReadOnlyConfig):
        raise AWXVerificationError("invalid_config")
    if not all(_valid_id(v) for v in (
        config.job_template_id, config.inventory_id, config.project_id
    )):
        raise AWXVerificationError("invalid_config")
    base = config.base_url
    if not isinstance(base, str) or len(base) > 253 or base != base.strip():
        raise AWXVerificationError("invalid_awx_url")
    try:
        parts = urllib.parse.urlsplit(base)
        port = parts.port
    except ValueError:
        raise AWXVerificationError("invalid_awx_url") from None
    if (parts.scheme != "https" or not parts.hostname or parts.username
            or parts.password or parts.path not in ("", "/")
            or parts.query or parts.fragment or (port is not None and not 1 <= port <= 65535)):
        raise AWXVerificationError("invalid_awx_url")
    if (not isinstance(config.token_file, Path) or not config.token_file.is_absolute()
            or (config.ca_file is not None and
                (not isinstance(config.ca_file, Path) or not config.ca_file.is_absolute()))):
        raise AWXVerificationError("invalid_config")
    return base.rstrip("/")


def _read_token(path: Path) -> str:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise AWXVerificationError("unsafe_token_permissions")
        with path.open("rb") as fh:
            data = fh.read(4097)
    except OSError:
        raise AWXVerificationError("token_unavailable") from None
    if len(data) > 4096:
        raise AWXVerificationError("token_unavailable")
    try:
        token = data.decode("ascii").strip("\r\n")
    except UnicodeDecodeError:
        raise AWXVerificationError("token_unavailable") from None
    if not token or any(ch.isspace() or ord(ch) < 33 or ord(ch) > 126 for ch in token):
        raise AWXVerificationError("token_unavailable")
    return token


class _BlockRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener(config: AWXReadOnlyConfig):
    try:
        context = ssl.create_default_context(
            cafile=str(config.ca_file) if config.ca_file is not None else None
        )
    except (OSError, ssl.SSLError):
        raise AWXVerificationError("ca_unavailable") from None
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        _BlockRedirects(),
    )


def _fetch(opener: Any, url: str, token: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
        method="GET",
    )
    try:
        with opener.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            if response.status != 200:
                raise AWXVerificationError("awx_unavailable")
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except (urllib.error.HTTPError, urllib.error.URLError, OSError, TimeoutError):
        raise AWXVerificationError("awx_unavailable") from None
    if len(body) > MAX_RESPONSE_BYTES:
        raise AWXVerificationError("awx_response_too_large")
    try:
        value = json.loads(body)
    except (UnicodeError, ValueError):
        raise AWXVerificationError("invalid_awx_response") from None
    if type(value) is not dict:
        raise AWXVerificationError("invalid_awx_response")
    return value


def verify_snapshot(
    *, job_id: int, job: Any, events_page: Any,
    config: AWXReadOnlyConfig, now: datetime | None = None,
) -> VerifiedLokiObservation:
    """Valida estructura de snapshots; no prueba autenticación por sí solo.

    Solo fetch_verified_observation obtiene snapshots desde el AWX real con
    TLS y un token read-only. No usar esta función como certificado de origen.
    """
    _config_base(config)
    if not _valid_id(job_id) or type(job) is not dict or type(events_page) is not dict:
        raise AWXVerificationError("invalid_job_payload")
    required_ids = (
        ("id", job_id),
        ("job_template", config.job_template_id),
        ("inventory", config.inventory_id),
        ("project", config.project_id),
    )
    if any(type(job.get(k)) is not int or job[k] != expected for k, expected in required_ids):
        raise AWXVerificationError("job_identity_mismatch")
    if (job.get("status") != "successful" or job.get("job_type") != "run"
            or job.get("launch_type") != "manual"
            or job.get("playbook") != JOB_PLAYBOOK
            or job.get("failed") is True):
        raise AWXVerificationError("job_not_authorized_or_successful")
    if job.get("limit") not in ("", JOB_HOST):
        raise AWXVerificationError("job_limit_mismatch")
    current = datetime.now(timezone.utc) if now is None else now
    if not isinstance(current, datetime) or current.tzinfo is None:
        raise AWXVerificationError("invalid_timestamp")
    current = current.astimezone(timezone.utc)
    started, finished = _utc(job.get("started")), _utc(job.get("finished"))
    age = (current - finished).total_seconds()
    if not (started <= finished and 0 <= age <= MAX_OBSERVATION_AGE_SECONDS):
        raise AWXVerificationError("stale_or_invalid_job")

    results = events_page.get("results")
    if (type(events_page.get("count")) is not int or type(results) is not list
            or events_page.get("next") is not None or events_page["count"] != len(results)
            or len(results) > MAX_JOB_EVENTS):
        raise AWXVerificationError("incomplete_job_events")

    matches = []
    for event in results:
        if type(event) is not dict:
            raise AWXVerificationError("invalid_job_event")
        data = event.get("event_data")
        if (type(data) is dict and data.get("task") == TASK_NAME
                and event.get("event") == "runner_on_ok"):
            if (type(event.get("job")) is not int or event["job"] != job_id
                    or data.get("host") != JOB_HOST):
                raise AWXVerificationError("event_identity_mismatch")
            msg = data.get("res", {}).get("msg") if type(data.get("res")) is dict else None
            matches.append(msg)
    if len(matches) != 1 or type(matches[0]) is not dict:
        raise AWXVerificationError("observation_event_missing_or_duplicated")
    message = matches[0]
    if (message.get("version") != DIAGNOSTIC_VERSION
            or message.get("type") != "observation_only"
            or message.get("verified_provenance") is not False
            or message.get("requires_external_job_validation") is not True
            or any(message.get(field) is not False for field in (
                "changes_kubernetes", "changes_triage", "changes_notifications",
                "execution_allowed"
            ))):
        raise AWXVerificationError("invalid_diagnostic_contract")
    observation = message.get("observation")
    if type(observation) is not dict or set(observation) != {
        "source", "namespace", "pod", "container", "pod_found",
        "container_found", "ready", "observed_at_utc"
    }:
        raise AWXVerificationError("invalid_observation")
    if (observation.get("source") != "kubernetes_api"
            or observation.get("namespace") != "logging"
            or observation.get("pod") != "loki-0"
            or observation.get("container") != "loki"
            or any(type(observation.get(field)) is not bool for field in (
                "pod_found", "container_found"
            ))):
        raise AWXVerificationError("observation_scope_mismatch")
    if observation["pod_found"] is False and observation["container_found"] is True:
        raise AWXVerificationError("invalid_observation")
    ready = observation.get("ready")
    if ready is not None and type(ready) is not bool:
        raise AWXVerificationError("invalid_observation")
    if ready is not None and not (observation["pod_found"] and observation["container_found"]):
        raise AWXVerificationError("invalid_observation")
    observed = _utc(observation.get("observed_at_utc"))
    drift = timedelta(seconds=30)
    if not (started - drift <= observed <= finished + drift
            and timedelta(0) <= current - observed <= timedelta(seconds=MAX_OBSERVATION_AGE_SECONDS)):
        raise AWXVerificationError("observation_time_mismatch")
    return VerifiedLokiObservation(
        job_id=job_id,
        finished_at_utc=finished.isoformat(),
        observation={k: observation[k] for k in sorted(observation)},
    )


def fetch_verified_observation(
    *, job_id: int, config: AWXReadOnlyConfig, now: datetime | None = None,
) -> VerifiedLokiObservation:
    """ÚNICA entrada que autentica realmente contra AWX. Solo dos GET, sin redirects."""
    base = _config_base(config)
    if not _valid_id(job_id):
        raise AWXVerificationError("invalid_job_id")
    token = _read_token(config.token_file)
    opener = _opener(config)
    prefix = f"{base}/api/v2/jobs/{job_id}"
    job = _fetch(opener, prefix + "/", token)
    events = _fetch(opener, prefix + "/job_events/?page_size=200&page=1", token)
    return verify_snapshot(job_id=job_id, job=job, events_page=events,
                           config=config, now=now)

