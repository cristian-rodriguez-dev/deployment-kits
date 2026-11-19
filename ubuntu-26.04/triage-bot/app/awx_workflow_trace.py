"""Pilas Observabilidad / Bloque 19G — auditoría de aprobación AWX (solo lectura).

No inicia workflows, no aprueba, no ejecuta remediaciones, no modifica Smart
Triage ni los notificadores. La validación de procedencia requiere lecturas
HTTPS autenticadas de AWX; snapshots offline sirven SOLO para tests.

El posible vínculo a un incidente lo selecciona un operador y NO demuestra
que el workflow se haya lanzado como consecuencia de esa alerta.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.awx_loki_verification import (
    AWXReadOnlyConfig, AWXVerificationError, _config_base, _fetch,
    _opener, _read_token, _utc, _valid_id,
)
from app.remediation_loki_binding import (
    ALERT_TITLE, _read_incident, _reference_valid,
)

VERSION = 'loki-awx-workflow-trace-v1'
WF_PLAYBOOK = 'monitorizacion/playbooks/revalidar_loki_k3s_post_aprobacion.yml'
TASK_NAME = 'Mostrar resultado protegido de revalidacion, sin actuar'
MAX_JOB_EVENTS = 200
MAX_WORKFLOW_AGE = timedelta(days=7)  # Auditoría histórica, no autorización ejecutiva.
INCIDENT_LINK_WINDOW = timedelta(minutes=15)
CLOCK_SKEW = timedelta(seconds=30)


@dataclass(frozen=True)
class AWXWorkflowConfig:
    awx: AWXReadOnlyConfig
    workflow_template_id: int
    revalidation_template_id: int


class WorkflowTraceError(ValueError):
    """Solo códigos fijos; no incluir texto externo ni objetos AWX."""
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _require(predicate: bool, code: str) -> None:
    if not predicate:
        raise WorkflowTraceError(code)


def _id(value: Any) -> bool:
    return _valid_id(value)


def _date(value: Any) -> datetime:
    try:
        return _utc(value)
    except AWXVerificationError:
        raise WorkflowTraceError('invalid_timestamp') from None


def _page(page: Any, max_items: int) -> list[dict]:
    _require(type(page) is dict, 'invalid_page')
    results = page.get('results')
    _require(type(results) is list and len(results) <= max_items
             and type(page.get('count')) is int
             and page['count'] == len(results) and page.get('next') is None,
             'incomplete_page')
    _require(all(type(x) is dict for x in results), 'invalid_page')
    return results


def verify_workflow_snapshot(
    *, workflow_id: int, workflow: Any, nodes_page: Any,
    success_page: Any, always_page: Any, failure_page: Any,
    approval: Any, revalidation_job: Any, events_page: Any,
    config: AWXWorkflowConfig, now: datetime | None = None,
) -> dict:
    """Validación pura de snapshots; NO acredita autenticidad por sí sola."""
    _require(isinstance(config, AWXWorkflowConfig)
             and _id(config.workflow_template_id)
             and _id(config.revalidation_template_id)
             and config.awx.job_template_id == config.revalidation_template_id,
             'invalid_config')
    try:
        _config_base(config.awx)
    except AWXVerificationError:
        raise WorkflowTraceError('invalid_config') from None
    _require(_id(workflow_id) and type(workflow) is dict, 'invalid_workflow')
    _require(workflow.get('id') == workflow_id
             and type(workflow.get('id')) is int
             and workflow.get('workflow_job_template') == config.workflow_template_id
             and type(workflow.get('workflow_job_template')) is int
             and workflow.get('status') == 'successful'
             and workflow.get('launch_type') == 'manual'
             and workflow.get('failed') is not True,
             'workflow_not_authorized_or_successful')
    started = _date(workflow.get('started'))
    finished = _date(workflow.get('finished'))
    current = datetime.now(timezone.utc) if now is None else now
    _require(isinstance(current, datetime) and current.tzinfo is not None,
             'invalid_timestamp')
    current = current.astimezone(timezone.utc)
    _require(started <= finished <= current
             and current - finished <= MAX_WORKFLOW_AGE,
             'workflow_too_old_or_invalid')

    nodes = _page(nodes_page, 8)
    _require(len(nodes) == 2, 'unexpected_workflow_graph')
    _require(all(type(n.get('workflow_job')) is int
                 and n['workflow_job'] == workflow_id
                 and _id(n.get('id')) and _id(n.get('job'))
                 and n.get('do_not_run') is False for n in nodes),
             'invalid_workflow_nodes')
    _require(len({n['job'] for n in nodes}) == 2, 'invalid_workflow_nodes')
    _require(sum(type(n.get('unified_job_template')) is int
                 and n['unified_job_template'] == config.revalidation_template_id
                 for n in nodes) == 1, 'revalidation_node_missing')
    _require(type(approval) is dict and _id(approval.get('id'))
             and type(revalidation_job) is dict and _id(revalidation_job.get('id')),
             'invalid_child_job')
    approval_nodes = [n for n in nodes if n['job'] == approval['id']]
    job_nodes = [n for n in nodes if n['job'] == revalidation_job['id']]
    _require(len(approval_nodes) == len(job_nodes) == 1
             and approval_nodes[0]['id'] != job_nodes[0]['id'],
             'workflow_node_mismatch')
    # Los tres enlaces se consultan desde AWX, no desde campos declarados por el job.
    successes = _page(success_page, 8)
    _require(len(successes) == 1 and successes[0].get('id') == job_nodes[0]['id'],
             'approval_success_edge_missing')
    _require(not _page(always_page, 8) and not _page(failure_page, 8),
             'unsafe_approval_edges')
    _require(approval.get('status') == 'successful'
             and approval.get('timed_out') is False
             and _id(approval.get('approved_or_denied_by')),
             'approval_not_verified')
    # No almacenamos el usuario aprobador, solo que AWX registró uno válido.
    approved_at = _date(approval.get('modified'))
    _require(started <= approved_at <= finished, 'approval_time_mismatch')

    job = revalidation_job
    _require(job.get('status') == 'successful'
             and job.get('failed') is not True
             and job.get('launch_type') == 'workflow'
             and job.get('job_type') == 'run'
             and job.get('job_template') == config.revalidation_template_id
             and type(job.get('job_template')) is int
             and job.get('inventory') == config.awx.inventory_id
             and type(job.get('inventory')) is int
             and job.get('project') == config.awx.project_id
             and type(job.get('project')) is int
             and job.get('playbook') == WF_PLAYBOOK
             and job.get('limit') in ('', 'ansible_server'),
             'revalidation_job_mismatch')
    job_start, job_end = _date(job.get('started')), _date(job.get('finished'))
    _require(started <= approved_at <= job_start <= job_end <= finished,
             'execution_order_mismatch')
    events = _page(events_page, MAX_JOB_EVENTS)
    matches = []
    for ev in events:
        data = ev.get('event_data')
        if (ev.get('event') == 'runner_on_ok' and type(data) is dict
                and data.get('task') == TASK_NAME):
            _require(ev.get('job') == job['id'] and type(ev.get('job')) is int
                     and data.get('host') == 'ansible_server',
                     'revalidation_event_mismatch')
            res = data.get('res')
            _require(type(res) is dict, 'invalid_revalidation_event')
            matches.append(res.get('msg'))
    _require(len(matches) == 1 and type(matches[0]) is dict,
             'missing_revalidation_event')
    msg = matches[0]
    _require(msg.get('version') == 'loki-awx-postapproval-v1'
             and msg.get('type') == 'revalidation_only'
             and msg.get('approval_verified') is False
             and msg.get('requires_external_workflow_validation') is True
             and msg.get('requires_human_review') is True
             and all(msg.get(flag) is False for flag in (
                 'execution_allowed', 'action_executed', 'changes_kubernetes',
                 'changes_triage', 'changes_notifications'
             )), 'unsafe_revalidation_result')
    target = msg.get('target')
    _require(type(target) is dict and target == {
        'namespace': 'logging', 'pod': 'loki-0', 'container': 'loki',
    }, 'revalidation_target_mismatch')
    observation = msg.get('observation')
    _require(type(observation) is dict and set(observation) == {
        'observed_at_utc', 'pod_found', 'container_found', 'ready'
    } and type(observation['pod_found']) is bool
             and type(observation['container_found']) is bool
             and (observation['ready'] is None or type(observation['ready']) is bool)
             and (observation['ready'] is None or
                  (observation['pod_found'] and observation['container_found']))
             and (observation['container_found'] is False or observation['pod_found']),
             'invalid_observation')
    observed_at = _date(observation['observed_at_utc'])
    _require(job_start - CLOCK_SKEW <= observed_at <= job_end + CLOCK_SKEW,
             'observation_time_mismatch')
    ready = observation['ready']
    expected_status = 'no_action' if ready is True else 'investigate'
    expected_reason = ('loki_ready' if ready is True else
                       'loki_not_ready_requires_investigation' if ready is False else
                       'loki_readiness_unknown')
    _require(msg.get('status') == expected_status
             and msg.get('reason_code') == expected_reason,
             'status_inconsistent')
    return {
        'version': VERSION,
        'workflow_id': workflow_id,
        'workflow_template_id': config.workflow_template_id,
        'approval_confirmed': True,
        'revalidation_job_id': job['id'],
        'job_provenance_verified': True,
        'workflow_started_at_utc': started.isoformat(),
        'workflow_finished_at_utc': finished.isoformat(),
        'observed_at_utc': observed_at.isoformat(),
        'target': {'namespace': 'logging', 'pod': 'loki-0', 'container': 'loki'},
        'ready': ready,
        'status': expected_status,
        'reason_code': expected_reason,
        'execution_allowed': False,
        'action_executed': False,
        'requires_human_review': True,
        'incident_linkage': 'not_assessed',
    }


def fetch_workflow_trace(
    *, workflow_id: int, config: AWXWorkflowConfig,
    now: datetime | None = None,
) -> dict:
    """Única entrada que verifica procedencia en AWX (8 GET autenticados)."""
    _require(_id(workflow_id), 'invalid_workflow_id')
    try:
        base = _config_base(config.awx)
        token = _read_token(config.awx.token_file)
        opener = _opener(config.awx)
    except AWXVerificationError as exc:
        raise WorkflowTraceError(exc.code) from None
    def get(path: str) -> dict:
        try:
            return _fetch(opener, f'{base}/api/v2/{path}', token)
        except AWXVerificationError as exc:
            raise WorkflowTraceError(exc.code) from None
    wf = get(f'workflow_jobs/{workflow_id}/')
    node_page = get(f'workflow_jobs/{workflow_id}/workflow_nodes/?page_size=8&page=1')
    nodes = _page(node_page, 8)
    _require(len(nodes) == 2, 'unexpected_workflow_graph')
    ids = [n.get('job') for n in nodes]
    _require(all(_id(i) for i in ids) and len(set(ids)) == 2, 'invalid_workflow_nodes')
    # El UJT de la revalidación está fijado en configuración. Evita sondear
    # endpoints del tipo incorrecto o adivinar el tipo del job por su título.
    job_nodes = [n for n in nodes if type(n.get('unified_job_template')) is int
                 and n['unified_job_template'] == config.revalidation_template_id]
    _require(len(job_nodes) == 1 and _id(job_nodes[0].get('job')),
             'revalidation_node_missing')
    revalidation_id = job_nodes[0]['job']
    approval_nodes = [n for n in nodes if n['id'] != job_nodes[0]['id']]
    _require(len(approval_nodes) == 1 and _id(approval_nodes[0].get('job')),
             'approval_node_missing')
    approval_node = approval_nodes[0]
    approval_id = approval_node['job']
    job = get(f'jobs/{revalidation_id}/')
    approval = get(f'workflow_approvals/{approval_id}/')
    prefix = f'workflow_job_nodes/{approval_node["id"]}/'
    success = get(prefix + 'success_nodes/?page_size=8&page=1')
    always = get(prefix + 'always_nodes/?page_size=8&page=1')
    failure = get(prefix + 'failure_nodes/?page_size=8&page=1')
    events = get(f'jobs/{revalidation_id}/job_events/?page_size=200&page=1')
    return verify_workflow_snapshot(
        workflow_id=workflow_id, workflow=wf, nodes_page=node_page,
        success_page=success, always_page=always, failure_page=failure,
        approval=approval, revalidation_job=job, events_page=events,
        config=config, now=now,
    )


def link_incident_operator_selected(
    *, trace: dict, incident_id: int, db_path: Path,
    now: datetime | None = None,
) -> dict:
    """Asociación MANUAL temporal. No convierte una coincidencia en causalidad."""
    _require(type(trace) is dict and trace.get('version') == VERSION
             and trace.get('approval_confirmed') is True
             and trace.get('job_provenance_verified') is True
             and trace.get('execution_allowed') is False
             and _id(trace.get('workflow_id')),
             'invalid_trace')
    _require(_id(incident_id), 'invalid_incident_id')
    try:
        incident = _read_incident(db_path, incident_id)
    except (OSError, ValueError, sqlite3.Error):
        incident = None
    _require(incident is not None, 'incident_unavailable')
    source, synthetic, title, received, analysis = incident
    _require(source == 'grafana' and synthetic == 0 and title == ALERT_TITLE,
             'unsupported_incident')
    try:
        obj = json.loads(analysis)
    except (ValueError, TypeError):
        obj = None
    _require(type(obj) is dict and _reference_valid(obj.get('grafana_loki_reference')),
             'invalid_incident_reference')
    triage = obj.get('triage')
    _require(type(triage) is dict and triage.get('decision') in ('notify', 'review'),
             'incident_not_eligible')
    received_at = _date(received)
    wf_started = _date(trace['workflow_started_at_utc'])
    wf_finished = _date(trace['workflow_finished_at_utc'])
    observed = _date(trace['observed_at_utc'])
    alert_start = _date(obj['grafana_loki_reference']['starts_at_utc'])
    current = datetime.now(timezone.utc) if now is None else now
    _require(isinstance(current, datetime) and current.tzinfo is not None,
             'invalid_timestamp')
    current = current.astimezone(timezone.utc)
    _require(alert_start <= received_at + timedelta(minutes=2)
             and received_at - CLOCK_SKEW <= wf_started <= wf_finished
             and wf_started - received_at <= INCIDENT_LINK_WINDOW
             and observed >= received_at - CLOCK_SKEW
             and wf_finished <= current,
             'incident_workflow_time_mismatch')
    return {**trace, 'incident_id': incident_id,
            'incident_linkage': 'operator_selected_temporal_not_causal'}


def record_workflow_trace(*, db_path: Path, trace: dict, now: datetime | None = None) -> bool:
    """Registro opt-in mínimo; no cambia incidentes, notificaciones ni políticas."""
    _require(type(trace) is dict and trace.get('version') == VERSION
             and trace.get('approval_confirmed') is True
             and trace.get('job_provenance_verified') is True
             and trace.get('execution_allowed') is False
             and trace.get('action_executed') is False
             and _id(trace.get('workflow_id'))
             and _id(trace.get('revalidation_job_id'))
             and trace.get('incident_linkage') in (
                 'not_assessed', 'operator_selected_temporal_not_causal'),
             'invalid_trace')
    _require(isinstance(db_path, Path) and db_path.is_absolute()
             and db_path.is_file() and not db_path.is_symlink(),
             'invalid_db_path')
    date = datetime.now(timezone.utc) if now is None else now
    _require(isinstance(date, datetime) and date.tzinfo is not None,
             'invalid_timestamp')
    ident = trace.get('incident_id')
    _require(ident is None or (_id(ident) and
             trace['incident_linkage'] == 'operator_selected_temporal_not_causal'),
             'invalid_incident_linkage')
    with sqlite3.connect(db_path, timeout=5) as con:
        con.execute('PRAGMA busy_timeout=5000')
        con.execute('''CREATE TABLE IF NOT EXISTS remediation_workflow_traces (
            workflow_id INTEGER PRIMARY KEY,
            incident_id INTEGER,
            revalidation_job_id INTEGER NOT NULL UNIQUE,
            recorded_at_utc TEXT NOT NULL,
            workflow_finished_at_utc TEXT NOT NULL,
            observed_at_utc TEXT NOT NULL,
            status TEXT NOT NULL,
            reason_code TEXT NOT NULL,
            incident_linkage TEXT NOT NULL,
            approval_confirmed INTEGER NOT NULL CHECK(approval_confirmed = 1),
            execution_allowed INTEGER NOT NULL CHECK(execution_allowed = 0),
            action_executed INTEGER NOT NULL CHECK(action_executed = 0)
        )''')
        cursor = con.execute('''INSERT OR IGNORE INTO remediation_workflow_traces
            (workflow_id, incident_id, revalidation_job_id, recorded_at_utc,
             workflow_finished_at_utc, observed_at_utc, status, reason_code,
             incident_linkage, approval_confirmed, execution_allowed, action_executed)
            VALUES(?,?,?,?,?,?,?,?,?,1,0,0)''', (
                trace['workflow_id'], ident, trace['revalidation_job_id'],
                date.astimezone(timezone.utc).isoformat(),
                trace['workflow_finished_at_utc'], trace['observed_at_utc'],
                trace['status'], trace['reason_code'], trace['incident_linkage'],
            ))
        return cursor.rowcount == 1


def main() -> int:
    parser = argparse.ArgumentParser(description='19G: auditoría AWX approval + revalidación, solo lectura')
    parser.add_argument('--workflow-id', type=int, required=True)
    parser.add_argument('--workflow-template-id', type=int, required=True)
    parser.add_argument('--job-template-id', type=int, required=True, help='JT revalidación 19F')
    parser.add_argument('--inventory-id', type=int, required=True)
    parser.add_argument('--project-id', type=int, required=True)
    parser.add_argument('--awx-url', required=True)
    parser.add_argument('--awx-token-file', type=Path, required=True)
    parser.add_argument('--awx-ca-file', type=Path)
    parser.add_argument('--db', type=Path)
    parser.add_argument('--incident-id', type=int, help='Solo vínculo manual a alerta Loki elegible')
    parser.add_argument('--record', action='store_true', help='Opt-in escritura mínima en SQLite')
    args = parser.parse_args()
    cfg = AWXWorkflowConfig(
        AWXReadOnlyConfig(args.awx_url, args.awx_token_file, args.awx_ca_file,
                          args.job_template_id, args.inventory_id, args.project_id),
        args.workflow_template_id, args.job_template_id,
    )
    try:
        trace = fetch_workflow_trace(workflow_id=args.workflow_id, config=cfg)
        if args.incident_id is not None:
            _require(args.db is not None, 'db_required_for_incident_linkage')
            trace = link_incident_operator_selected(
                trace=trace, incident_id=args.incident_id, db_path=args.db,
            )
        if args.record:
            _require(args.db is not None, 'db_required_for_record')
            trace['record_created'] = record_workflow_trace(db_path=args.db, trace=trace)
        print(json.dumps(trace, ensure_ascii=True, sort_keys=True))
        return 0
    except WorkflowTraceError as exc:
        print(json.dumps({'version': VERSION, 'verified': False,
                          'reason_code': exc.code, 'execution_allowed': False},
                         sort_keys=True))
        return 2
    except (OSError, sqlite3.Error):
        print(json.dumps({'version': VERSION, 'verified': False,
                          'reason_code': 'local_resource_unavailable',
                          'execution_allowed': False}, sort_keys=True))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
