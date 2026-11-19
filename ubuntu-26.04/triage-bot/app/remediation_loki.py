"""Bloque 19B: propuesta informativa de diagnóstico de Loki en K3s.

Contrato PURO: no HTTP, AWX, shell, Kubernetes, base de datos ni notificaciones.
Las señales de Grafana NO acreditan el estado de Kubernetes. El integrador
futuro debe comprobar autenticación, vinculación del incidente y procedencia
de una observación independiente de la API Kubernetes antes de pasar
``observation_trusted=True``. Un booleano NO es prueba de esa procedencia.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from app.remediation_proposal import MAX_OBSERVATION_AGE_SECONDS, VERSION

RULE_UID = "awx-critical-loki-notready"
NAMESPACE = "logging"
POD = "loki-0"
CONTAINER = "loki"
ACTION = "diagnose_k3s_pod"  # Solo lectura, NO iniciar/reiniciar.


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or len(value) > 45:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.astimezone(timezone.utc) if dt.tzinfo is not None else None


def propose_loki_diagnostic(
    *,
    incident_id: int,
    signal: Mapping[str, Any] | None,
    observation: Mapping[str, Any] | None,
    observation_trusted: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Contrasta una señal concreta con una observación independiente validada.

    ``observation_trusted=True`` SOLO puede establecerlo una capa de confianza
    que haya autenticado la API de Kubernetes y comprobado identidad/alcance.
    Nunca copiar ese dato del webhook, de Gemini ni del propio ``observation``.
    No invocar desde ``main.py`` ni registrar como remediación operativa todavía.
    """
    valid_id = incident_id if type(incident_id) is int and incident_id > 0 else None
    result: dict[str, Any] = {
        "version": VERSION,
        "incident_id": valid_id,
        "status": "no_action",
        "action_id": None,
        "target": None,
        "reason_code": "invalid_input",
        "risk": None,
        "requires_approval": True,
        "execution_allowed": False,
    }
    if valid_id is None:
        return result
    if not isinstance(signal, dict):
        result.update(status="investigate", reason_code="missing_signal")
        return result
    if (signal.get("source") != "grafana"
            or signal.get("rule_uid") != RULE_UID
            or signal.get("component") != "loki"):
        result["reason_code"] = "unsupported_signal"
        return result
    if signal.get("status") == "resolved":
        result["reason_code"] = "signal_resolved"
        return result
    if signal.get("status") != "firing":
        result.update(status="investigate", reason_code="unknown_signal_state")
        return result
    if observation_trusted is not True:
        result.update(status="investigate", reason_code="untrusted_observation")
        return result
    if not isinstance(observation, dict):
        result.update(status="investigate", reason_code="missing_observation")
        return result
    if (observation.get("source") != "kubernetes_api"
            or observation.get("namespace") != NAMESPACE
            or observation.get("pod") != POD
            or observation.get("container") != CONTAINER):
        result.update(status="investigate", reason_code="observation_scope_mismatch")
        return result
    current = datetime.now(timezone.utc) if now is None else now
    if not isinstance(current, datetime) or current.tzinfo is None:
        result.update(status="investigate", reason_code="invalid_observation_time")
        return result
    observed_at = _timestamp(observation.get("observed_at_utc"))
    if observed_at is None:
        result.update(status="investigate", reason_code="invalid_observation_time")
        return result
    age_seconds = (current.astimezone(timezone.utc) - observed_at).total_seconds()
    if not 0 <= age_seconds <= MAX_OBSERVATION_AGE_SECONDS:
        result.update(status="investigate", reason_code="stale_or_future_observation")
        return result
    if (observation.get("pod_found") is not True
            or observation.get("container_found") is not True):
        result.update(status="investigate", reason_code="missing_target_in_kubernetes")
        return result
    ready = observation.get("ready")
    if type(ready) is not bool:
        result.update(status="investigate", reason_code="unknown_readiness")
        return result
    if ready:
        result["reason_code"] = "loki_currently_ready"
        return result
    result.update(
        status="proposed",
        action_id=ACTION,
        target={"namespace": NAMESPACE, "pod": POD, "container": CONTAINER},
        reason_code="loki_not_ready_confirmed",
        risk="low",  # Riesgo de DIAGNÓSTICO, no de reparación.
    )
    return result
