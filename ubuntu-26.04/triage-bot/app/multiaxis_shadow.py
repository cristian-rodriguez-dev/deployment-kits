"""Native, evidence-bounded three-axis Gemini shadow recommendation.

The result is purely advisory. No decisions, notifications, or actions are changed.
Model citations prove *availability of an observation*, not truth of the model's
reason or causality. Never pass raw provider objects into incident storage.
"""
from __future__ import annotations

from typing import Any

from app.ai_decision_shadow import DECISIONS, available_evidence_ids, validated_for_model
# This production path intentionally does not import the offline evaluator.
NOTIFICATIONS = frozenset({'notify', 'hold', 'suppress', 'undetermined'})
INVESTIGATIONS = frozenset({'required', 'not_required', 'undetermined'})
EVIDENCE_STATES = frozenset({'suspicious_unconfirmed', 'benign_supported', 'unknown'})

VERSION = 'ai-multiaxis-shadow-v1'
CONFIDENCES = frozenset({'low', 'medium', 'high'})
FIELDS = frozenset({
    'notification', 'investigation', 'evidence_state', 'confidence',
    'notification_reason', 'investigation_reason', 'evidence_reason',
    'notification_evidence_ids', 'investigation_evidence_ids',
    'evidence_state_evidence_ids',
})


def _reason(value: Any) -> bool:
    return (type(value) is str and 1 <= len(value.strip()) <= 240
            and len(value) <= 260 and not any(ord(x) < 32 for x in value))


def _citations(value: Any, available: set[str], required: bool) -> bool:
    return (type(value) is list and int(required) <= len(value) <= 4
            and all(type(v) is str and v in available for v in value)
            and len(set(value)) == len(value))


def validate(proposal: Any, facts: Any) -> dict | None:
    """Fail closed for unknown axes, mismatched citations and invented facts."""
    if (type(proposal) is not dict or set(proposal) != FIELDS
            or not validated_for_model(facts)):
        return None
    if (type(proposal['notification']) is not str
            or proposal['notification'] not in NOTIFICATIONS
            or type(proposal['investigation']) is not str
            or proposal['investigation'] not in INVESTIGATIONS
            or type(proposal['evidence_state']) is not str
            or proposal['evidence_state'] not in EVIDENCE_STATES
            or type(proposal['confidence']) is not str
            or proposal['confidence'] not in CONFIDENCES):
        return None
    for key in ('notification_reason', 'investigation_reason', 'evidence_reason'):
        if not _reason(proposal[key]):
            return None
    available = set(available_evidence_ids(facts))
    for axis, claim in (
        ('notification', proposal['notification'] != 'undetermined'),
        ('investigation', proposal['investigation'] != 'undetermined'),
        ('evidence_state', proposal['evidence_state'] != 'unknown'),
    ):
        if not _citations(proposal[axis + '_evidence_ids'], available, claim):
            return None
    # Keep precisely the enumerated axes, bounded explanatory text and citations.
    return {key: (
        list(proposal[key]) if key.endswith('_evidence_ids')
        else proposal[key].strip() if key.endswith('_reason')
        else proposal[key]
    ) for key in sorted(FIELDS)}


def compare(model: Any, current: str, facts: Any) -> dict:
    """Persist advisory-only comparison; never changes the active decision."""
    actual_notification = {'notify': 'notify', 'review': 'hold', 'suppress': 'suppress'}.get(current)
    out = {
        'version': VERSION, 'type': 'advisory_only', 'status': 'not_evaluated',
        'actual_policy_decision': current if current in DECISIONS else None,
        'actual_notification': actual_notification,
        'recommendation': None, 'notification_differs': None,
        'actual_investigation': None, 'actual_evidence_state': None,
        'requires_human_review': True,
        'reason_text_verified': False, 'causality_verified': False,
        'changes_triage': False, 'changes_notifications': False,
        'automatic_actions': False,
    }
    if actual_notification is None or not validated_for_model(facts):
        return out
    if type(model) is not dict or model.get('multiaxis_shadow_evidence_used') is not True:
        return out
    proposed = validate(model.get('multiaxis_shadow_recommendation'), facts)
    if proposed is None:
        out['status'] = 'invalid_or_unsupported_proposal'
        return out
    return {
        **out, 'status': 'evaluated', 'recommendation': proposed,
        'notification_differs': proposed['notification'] != actual_notification,
        'protected_notification_retained': (
            current == 'notify' and proposed['notification'] != 'notify'),
    }
