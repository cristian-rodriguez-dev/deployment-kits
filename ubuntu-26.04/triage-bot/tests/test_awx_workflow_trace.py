"""Pruebas offline; no contactan con AWX, Loki ni Gemini."""
from __future__ import annotations

import copy
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from app.awx_loki_verification import AWXReadOnlyConfig
from app.awx_workflow_trace import (
    AWXWorkflowConfig, WorkflowTraceError, fetch_workflow_trace,
    link_incident_operator_selected, record_workflow_trace,
    verify_workflow_snapshot,
)
from app.remediation_loki_binding import ALERT_TITLE, REFERENCE_VERSION
from app.remediation_loki import RULE_UID

NOW = datetime(2026, 11, 16, 14, 25, tzinfo=timezone.utc)


def fixtures():
    cfg = AWXWorkflowConfig(
        AWXReadOnlyConfig('https://192.168.56.20', Path('/tmp/awx-token'),
                          None, 206, 7, 5), 300, 206)
    wf = {'id': 900, 'workflow_job_template': 300, 'status': 'successful',
          'launch_type': 'manual', 'failed': False,
          'started': '2026-11-16T14:21:30Z',
          'finished': '2026-11-16T14:24:03Z'}
    nodes = {'count': 2, 'next': None, 'results': [
        {'id': 10, 'job': 901, 'workflow_job': 900,
         'unified_job_template': 410, 'do_not_run': False},
        {'id': 11, 'job': 902, 'workflow_job': 900,
         'unified_job_template': 206, 'do_not_run': False},
    ]}
    success = {'count': 1, 'next': None, 'results': [{'id': 11}]}
    empty = {'count': 0, 'next': None, 'results': []}
    approval = {'id': 901, 'status': 'successful', 'timed_out': False,
                'approved_or_denied_by': 32, 'modified': '2026-11-16T14:22:20Z'}
    job = {'id': 902, 'status': 'successful', 'failed': False,
           'launch_type': 'workflow', 'job_type': 'run', 'job_template': 206,
           'inventory': 7, 'project': 5,
           'playbook': 'monitorizacion/playbooks/revalidar_loki_k3s_post_aprobacion.yml',
           'limit': '', 'started': '2026-11-16T14:22:30Z',
           'finished': '2026-11-16T14:24:00Z'}
    msg = {'version': 'loki-awx-postapproval-v1', 'type': 'revalidation_only',
           'target': {'namespace': 'logging', 'pod': 'loki-0', 'container': 'loki'},
           'observation': {'observed_at_utc': '2026-11-16T14:23:39Z',
                           'pod_found': True, 'container_found': True, 'ready': True},
           'status': 'no_action', 'reason_code': 'loki_ready',
           'approval_verified': False, 'requires_external_workflow_validation': True,
           'requires_human_review': True, 'execution_allowed': False,
           'action_executed': False, 'changes_kubernetes': False,
           'changes_triage': False, 'changes_notifications': False}
    events = {'count': 1, 'next': None, 'results': [
        {'event': 'runner_on_ok', 'job': 902,
         'event_data': {'task': 'Mostrar resultado protegido de revalidacion, sin actuar',
                        'host': 'ansible_server', 'res': {'msg': msg}}},
    ]}
    return {'workflow_id': 900, 'workflow': wf, 'nodes_page': nodes,
            'success_page': success, 'always_page': copy.deepcopy(empty),
            'failure_page': copy.deepcopy(empty), 'approval': approval,
            'revalidation_job': job, 'events_page': events, 'config': cfg, 'now': NOW}


class SnapshotTests(unittest.TestCase):
    def test_valid_healthy(self):
        trace = verify_workflow_snapshot(**fixtures())
        self.assertTrue(trace['approval_confirmed'])
        self.assertFalse(trace['execution_allowed'])
        self.assertEqual(trace['status'], 'no_action')
        self.assertNotIn('approved_or_denied_by', trace)

    def test_valid_unhealthy(self):
        f = fixtures()
        msg = f['events_page']['results'][0]['event_data']['res']['msg']
        msg['observation']['ready'] = False
        msg['status'] = 'investigate'
        msg['reason_code'] = 'loki_not_ready_requires_investigation'
        self.assertEqual(verify_workflow_snapshot(**f)['status'], 'investigate')

    def test_valid_unknown_readiness(self):
        f = fixtures()
        msg = f['events_page']['results'][0]['event_data']['res']['msg']
        msg['observation']['ready'] = None
        msg['status'] = 'investigate'
        msg['reason_code'] = 'loki_readiness_unknown'
        self.assertEqual(verify_workflow_snapshot(**f)['status'], 'investigate')

    def test_bad_workflow_ids(self):
        for value in (0, True, '900', 901):
            with self.subTest(value=value):
                f = fixtures(); f['workflow_id'] = value
                with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_wrong_workflow_template(self):
        f = fixtures(); f['workflow']['workflow_job_template'] = 2
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_workflow_not_successful(self):
        for status in ('running', 'failed', 'canceled'):
            with self.subTest(status=status):
                f = fixtures(); f['workflow']['status'] = status
                with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_workflow_not_manual(self):
        f = fixtures(); f['workflow']['launch_type'] = 'scheduled'
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_workflow_stale(self):
        f = fixtures(); f['now'] = datetime(2026, 12, 1, tzinfo=timezone.utc)
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_more_nodes(self):
        f = fixtures(); f['nodes_page']['results'].append(dict(f['nodes_page']['results'][1], id=12))
        f['nodes_page']['count'] = 3
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_incomplete_nodes_page(self):
        f = fixtures(); f['nodes_page']['next'] = '/next/'
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_node_not_same_workflow(self):
        f = fixtures(); f['nodes_page']['results'][0]['workflow_job'] = 99
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_node_unrun(self):
        f = fixtures(); f['nodes_page']['results'][1]['do_not_run'] = True
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_job_node_wrong_template(self):
        f = fixtures(); f['nodes_page']['results'][1]['unified_job_template'] = 444
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_no_success_link(self):
        f = fixtures(); f['success_page'] = {'count': 0, 'next': None, 'results': []}
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_success_edge_wrong_child(self):
        f = fixtures(); f['success_page']['results'][0]['id'] = 10
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_disallowed_always_edge(self):
        f = fixtures(); f['always_page'] = {'count': 1, 'next': None, 'results': [{'id': 11}]}
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_disallowed_failure_edge(self):
        f = fixtures(); f['failure_page'] = {'count': 1, 'next': None, 'results': [{'id': 11}]}
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_approval_not_successful(self):
        f = fixtures(); f['approval']['status'] = 'failed'
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_no_approver(self):
        f = fixtures(); f['approval']['approved_or_denied_by'] = None
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_approval_timed_out(self):
        f = fixtures(); f['approval']['timed_out'] = True
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_job_not_workflow_launch(self):
        f = fixtures(); f['revalidation_job']['launch_type'] = 'manual'
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_job_wrong_playbook(self):
        f = fixtures(); f['revalidation_job']['playbook'] = 'other.yml'
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_approval_after_job_started(self):
        f = fixtures(); f['approval']['modified'] = '2026-11-16T14:23:00Z'
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_event_wrong_host(self):
        f = fixtures(); f['events_page']['results'][0]['event_data']['host'] = 'other'
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_unexpected_event_duplicates(self):
        f = fixtures(); f['events_page']['results'].append(f['events_page']['results'][0])
        f['events_page']['count'] = 2
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_event_no_revalidation(self):
        f = fixtures(); f['events_page']['results'][0]['event_data']['task'] = 'Other task'
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_faked_execution(self):
        f = fixtures(); f['events_page']['results'][0]['event_data']['res']['msg']['action_executed'] = True
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_contradictory_ready(self):
        f = fixtures(); f['events_page']['results'][0]['event_data']['res']['msg']['status'] = 'investigate'
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_ready_without_container(self):
        f = fixtures(); f['events_page']['results'][0]['event_data']['res']['msg']['observation']['container_found'] = False
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_broad_scope_target(self):
        f = fixtures(); f['events_page']['results'][0]['event_data']['res']['msg']['target']['namespace'] = 'default'
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_event_timestamp_not_from_job(self):
        f = fixtures(); f['events_page']['results'][0]['event_data']['res']['msg']['observation']['observed_at_utc'] = '2026-11-15T14:23:39Z'
        with self.assertRaises(WorkflowTraceError): verify_workflow_snapshot(**f)

    def test_fetch_uses_read_only_api(self):
        f = fixtures()
        responses = {
            'workflow_jobs/900/': f['workflow'],
            'workflow_jobs/900/workflow_nodes/?page_size=8&page=1': f['nodes_page'],
            'jobs/902/': f['revalidation_job'],
            'workflow_approvals/901/': f['approval'],
            'workflow_job_nodes/10/success_nodes/?page_size=8&page=1': f['success_page'],
            'workflow_job_nodes/10/always_nodes/?page_size=8&page=1': f['always_page'],
            'workflow_job_nodes/10/failure_nodes/?page_size=8&page=1': f['failure_page'],
            'jobs/902/job_events/?page_size=200&page=1': f['events_page'],
        }
        calls = []
        def fake_fetch(opener, url, token):
            self.assertTrue(url.startswith('https://192.168.56.20/api/v2/'))
            self.assertEqual(token, 'fake-test-token')
            path = url.split('/api/v2/', 1)[1]
            calls.append(path)
            return copy.deepcopy(responses[path])
        with patch('app.awx_workflow_trace._read_token', return_value='fake-test-token'), \
             patch('app.awx_workflow_trace._opener', return_value=object()), \
             patch('app.awx_workflow_trace._fetch', side_effect=fake_fetch):
            result = fetch_workflow_trace(workflow_id=900, config=f['config'], now=NOW)
        self.assertTrue(result['approval_confirmed'])
        self.assertEqual(set(calls), set(responses))
        self.assertEqual(len(calls), 8)


class LinkageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / 'incidents.db'
        with sqlite3.connect(self.db) as con:
            con.execute('''CREATE TABLE incidents (id INTEGER PRIMARY KEY, source TEXT,
                synthetic INTEGER, title TEXT, received_at TEXT, analysis TEXT)''')
            con.execute('INSERT INTO incidents VALUES (?,?,?,?,?,?)', (
                19, 'grafana', 0, ALERT_TITLE, '2026-11-16T14:20:00Z',
                json.dumps({'triage': {'decision': 'notify'},
                    'grafana_loki_reference': {
                        'version': REFERENCE_VERSION,
                        'source': 'grafana_webhook_claim', 'rule_uid': RULE_UID,
                        'component': 'loki', 'status': 'firing',
                        'starts_at_utc': '2026-11-16T14:19:00+00:00',
                        'fingerprint_sha256': 'a' * 64,
                    }}),
            ))

    def trace(self):
        return verify_workflow_snapshot(**fixtures())

    def test_link_operator_selected_not_causal(self):
        linked = link_incident_operator_selected(trace=self.trace(), incident_id=19,
                                                  db_path=self.db, now=NOW)
        self.assertEqual(linked['incident_linkage'], 'operator_selected_temporal_not_causal')
        self.assertFalse(linked['execution_allowed'])

    def test_missing_incident(self):
        with self.assertRaises(WorkflowTraceError):
            link_incident_operator_selected(trace=self.trace(), incident_id=20,
                                            db_path=self.db, now=NOW)

    def test_synthetic_rejected(self):
        with sqlite3.connect(self.db) as con:
            con.execute('UPDATE incidents SET synthetic=1 WHERE id=19')
        with self.assertRaises(WorkflowTraceError):
            link_incident_operator_selected(trace=self.trace(), incident_id=19,
                                            db_path=self.db, now=NOW)

    def test_missing_uid_rejected(self):
        with sqlite3.connect(self.db) as con:
            con.execute('UPDATE incidents SET analysis=? WHERE id=19', ('{}',))
        with self.assertRaises(WorkflowTraceError):
            link_incident_operator_selected(trace=self.trace(), incident_id=19,
                                            db_path=self.db, now=NOW)

    def test_unrelated_incident_time(self):
        with sqlite3.connect(self.db) as con:
            con.execute('UPDATE incidents SET received_at=? WHERE id=19',
                        ('2026-11-15T14:00:00Z',))
        with self.assertRaises(WorkflowTraceError):
            link_incident_operator_selected(trace=self.trace(), incident_id=19,
                                            db_path=self.db, now=NOW)

    def test_record_trace_opt_in_append_only(self):
        result = self.trace()
        self.assertTrue(record_workflow_trace(db_path=self.db, trace=result, now=NOW))
        self.assertFalse(record_workflow_trace(db_path=self.db, trace=result, now=NOW))
        with sqlite3.connect(self.db) as con:
            row = con.execute('SELECT workflow_id, incident_id, approval_confirmed, action_executed FROM remediation_workflow_traces').fetchone()
            self.assertEqual(row, (900, None, 1, 0))

    def test_record_selected_link(self):
        result = link_incident_operator_selected(trace=self.trace(), incident_id=19,
                                                  db_path=self.db, now=NOW)
        self.assertTrue(record_workflow_trace(db_path=self.db, trace=result, now=NOW))
        with sqlite3.connect(self.db) as con:
            self.assertEqual(con.execute('SELECT incident_id FROM remediation_workflow_traces').fetchone()[0], 19)

    def test_record_rejects_execution(self):
        result = self.trace(); result['execution_allowed'] = True
        with self.assertRaises(WorkflowTraceError):
            record_workflow_trace(db_path=self.db, trace=result, now=NOW)

    def test_record_bad_db(self):
        with self.assertRaises(WorkflowTraceError):
            record_workflow_trace(db_path=Path('/definitely/not/a/db'), trace=self.trace(), now=NOW)


if __name__ == '__main__':
    unittest.main()
