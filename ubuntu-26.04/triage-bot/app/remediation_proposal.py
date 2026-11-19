"""Bloque 19: propuestas deterministas de diagnóstico, sin ejecución ni AWX.

Este módulo NO debe invocarse directamente con datos arbitrarios de webhooks.
La identidad debe verificarse previamente por una fuente de confianza, y la
observación debe proceder de un diagnóstico autenticado. Este contrato no
valida por sí mismo el origen de los datos.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Mapping

VERSION = "remediation-proposal-v1"
ACTION = "diagnose_service"  # Solo diagnóstico. No arranque/reinicio.
ALLOWED_SERVICES = frozenset({"alloy.service"})
MAX_OBSERVATION_AGE_SECONDS = 300
_HOST = re.compile(r"[A-Za-z0-9_.-]{2,100}\Z")
_DEPARTMENT = re.compile(r"[A-Za-z0-9À-ÿ_. -]{2,80}\Z")
_BAD_DEPARTMENTS = frozenset({"unknown", "sin asignar", "desconocido", "n/d"})


def _valid_identity(asset: Any) -> bool:
    if not isinstance(asset, dict):
        return False
    host, department = asset.get("name"), asset.get("department")
    if not isinstance(host, str) or not isinstance(department, str):
        return False
    if (host != host.strip() or department != department.strip()
            or not _HOST.fullmatch(host) or host.isdecimal()
            or not _DEPARTMENT.fullmatch(department)
            or department.casefold() in _BAD_DEPARTMENTS):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return True
    return False  # Una IP no acredita por sí sola identidad del host.


def _utc_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or len(value) > 45:
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result.astimezone(timezone.utc) if result.tzinfo is not None else None


def propose(
    *,
    incident_id: int,
    asset: Mapping[str, Any] | None,
    identity_verified: bool = False,
    observation: Mapping[str, Any] | None = None,
    requested_action: str = ACTION,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Emite una propuesta informativa; nunca ejecuta ni encola acciones.

    `identity_verified=True` debe ser establecido SOLO por el integrador tras
    verificar identidad de forma independiente, nunca copiando el webhook/LLM.
    Lo mismo se aplica a la procedencia del objeto `observation`.
    """
    safe_id = incident_id if type(incident_id) is int and incident_id > 0 else None
    output: dict[str, Any] = {
        "version": VERSION,
        "incident_id": safe_id,
        "status": "no_action",
        "action_id": None,
        "target": None,
        "reason_code": "invalid_input",
        "risk": None,
        "requires_approval": True,
        "execution_allowed": False,
    }
    if safe_id is None:
        return output
    if requested_action != ACTION:
        output["reason_code"] = "action_not_allowed"
        return output
    if not isinstance(observation, dict):
        output.update(status="investigate", reason_code="missing_observation")
        return output
    service = observation.get("service")
    if not isinstance(service, str) or service not in ALLOWED_SERVICES:
        output["reason_code"] = "service_not_allowed"
        return output
    if identity_verified is not True or not _valid_identity(asset):
        output.update(status="investigate", reason_code="unverified_asset_identity")
        return output
    assert isinstance(asset, dict)  # El contrato de _valid_identity ya lo exige.
    if (observation.get("source") != "systemd"
            or observation.get("host") != asset["name"]
            or observation.get("department") != asset["department"]):
        output.update(status="investigate", reason_code="unverified_observation_scope")
        return output
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        output.update(status="investigate", reason_code="invalid_observation_time")
        return output
    observed = _utc_time(observation.get("observed_at_utc"))
    if observed is None:
        output.update(status="investigate", reason_code="invalid_observation_time")
        return output
    age = (current.astimezone(timezone.utc) - observed).total_seconds()
    if age < 0 or age > MAX_OBSERVATION_AGE_SECONDS:
        output.update(status="investigate", reason_code="stale_or_future_observation")
        return output
    state = observation.get("state")
    if state in ("active", "activating"):
        output["reason_code"] = "service_not_inactive"
        return output
    if state not in ("inactive", "failed"):
        output.update(status="investigate", reason_code="unknown_service_state")
        return output
    output.update(
        status="proposed",
        action_id=ACTION,
        target={"asset_id": asset["name"], "department": asset["department"], "service": service},
        reason_code="service_inactive",
        risk="low",  # Bajo riesgo del diagnóstico propuesto, no de una recuperación.
    )
    return output
