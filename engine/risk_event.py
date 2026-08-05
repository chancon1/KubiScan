"""Turn scored RBAC findings into compact, structured risk events.

The scanner historically reported one whole Role or ClusterRole.  That is a
useful inventory view, but it joins together grants with very different reach:
one ClusterRole may be namespaced through a RoleBinding and cluster-wide
through a ClusterRoleBinding.  A risk event is deliberately narrower:

    one risky pattern x one role x one binding

This module is a presentation layer over the existing matcher and scorer.  It
does not replace the legacy reports and it never mutates their Role objects.
"""

import hashlib

from engine.scoring import score_findings_for_scope
from misc.constants import (CLUSTER_ROLE_BINDING_KIND, GROUP_KIND, ROLE_KIND,
                            SERVICEACCOUNT_KIND)


STATUS_ACTIVE = 'ACTIVE'
STATUS_LATENT = 'LATENT'
EVENT_SCHEMA_VERSION = 2


_CATEGORY_IMPACT = {
    'availability': 'The permission can disrupt workloads or cluster availability.',
    'control-plane': 'The permission reaches a Kubernetes control-plane interface.',
    'credential-access': 'The permission can expose credentials or authentication material.',
    'data-access': 'The permission can expose application or cluster data.',
    'network': 'The permission can change or bypass network controls.',
    'observability': 'The permission exposes operational data about the cluster.',
    'policy-bypass': 'The permission can weaken or bypass a security policy.',
    'privilege-escalation': 'The permission can contribute to privilege escalation.',
    'recon': 'The permission exposes information useful for cluster reconnaissance.',
    'workload-execution': 'The permission can create or control executable workloads.',
}


def _subject_display(subject, binding_namespace=None):
    kind = getattr(subject, 'kind', None) or 'Subject'
    name = getattr(subject, 'name', None) or 'unknown'
    if kind == SERVICEACCOUNT_KIND:
        namespace = getattr(subject, 'namespace', None) or binding_namespace or 'unknown'
        return 'ServiceAccount {0}/{1}'.format(namespace, name)
    return '{0} {1}'.format(kind, name)


def _subject_summary(subjects, binding_namespace=None):
    subjects = list(subjects or [])
    for subject in subjects:
        if getattr(subject, 'kind', None) != GROUP_KIND:
            continue
        if getattr(subject, 'name', None) == 'system:unauthenticated':
            return 'Unauthenticated users'
        if getattr(subject, 'name', None) == 'system:authenticated':
            return 'All authenticated users'
    if len(subjects) == 1:
        return _subject_display(subjects[0], binding_namespace)
    if subjects:
        return '{0} subjects'.format(len(subjects))
    return 'No subject'


def _exposure_order(subjects):
    """Broad identities sort before individual principals at the same risk."""
    subjects = list(subjects or [])
    pairs = set((getattr(subject, 'kind', None), getattr(subject, 'name', None))
                for subject in subjects)
    if (GROUP_KIND, 'system:unauthenticated') in pairs:
        return 0
    if (GROUP_KIND, 'system:authenticated') in pairs:
        return 1
    if any(kind == GROUP_KIND for kind, name in pairs):
        return 2
    if len(subjects) > 1:
        return 3
    if subjects:
        return 4
    return 5


def _joined(values):
    values = list(values or [])
    if not values:
        return 'unknown'
    return '/'.join(values)


def _capability_from_matches(finding):
    """A compact verb phrase for a Summary when YAML has no hand-written one."""
    if finding.pattern.summary:
        return finding.pattern.summary
    matches = list(finding.rule_matches or [])
    if len(matches) != 1:
        category = (finding.category or 'risky').replace('-', ' ')
        return 'hold a {0} permission chain'.format(category)
    match = matches[0]
    verbs = _joined(match.matched_verbs)
    targets = list(match.matched_resources or [])
    if not targets:
        targets = list(getattr(match.source_rule, 'non_resource_ur_ls', None) or [])
    return '{0} {1}'.format(verbs, _joined(targets))


def _scope_for(role, binding):
    if binding is None:
        if role.kind == ROLE_KIND:
            return 'namespace {0} if bound'.format(role.namespace)
        return 'cluster-wide if bound by a ClusterRoleBinding'
    if not binding.subjects:
        if binding.kind == CLUSTER_ROLE_BINDING_KIND:
            return 'cluster-wide if subjects are added'
        return 'namespace {0} if subjects are added'.format(binding.namespace)
    if binding.kind == CLUSTER_ROLE_BINDING_KIND:
        return 'cluster-wide'
    return 'namespace {0}'.format(binding.namespace)


def _scope_suffix(scope):
    if scope == 'cluster-wide':
        return ' cluster-wide'
    if scope.startswith('namespace '):
        return ' in {0}'.format(scope)
    return ''


def _role_display(role):
    if role.kind == ROLE_KIND:
        return 'Role {0}/{1}'.format(role.namespace, role.name)
    return 'ClusterRole {0}'.format(role.name)


def _binding_display(binding):
    if binding is None:
        return 'none'
    if binding.kind == CLUSTER_ROLE_BINDING_KIND:
        return 'ClusterRoleBinding {0}'.format(binding.name)
    return 'RoleBinding {0}/{1}'.format(binding.namespace, binding.name)


def _creation_time(value):
    if value is None:
        return None
    isoformat = getattr(value, 'isoformat', None)
    if isoformat is None:
        return str(value)
    rendered = isoformat()
    if getattr(value, 'tzinfo', None) is None:
        return rendered + 'Z'
    return rendered.replace('+00:00', 'Z')


def _sentence(value):
    value = (value or '').strip()
    if not value:
        return value
    value = value[0].upper() + value[1:]
    return value if value.endswith(('.', '!', '?')) else value + '.'


def _dedupe(values):
    result = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _stable_event_id(finding, role, binding):
    parts = [
        finding.pattern_name,
        role.kind or '',
        role.namespace or '',
        role.name or '',
        binding.kind if binding is not None else '',
        binding.namespace if binding is not None and binding.namespace is not None else '',
        binding.name if binding is not None else '',
    ]
    raw = '\x1f'.join(parts).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


class RiskEvent(object):
    """One directly reviewable RBAC grant and the reason it was prioritised."""

    def __init__(self, event_id, summary, priority, score, status, risk_name, category,
                 subjects, permissions, role, binding, scope, reasons,
                 role_creation_time=None, binding_creation_time=None,
                 exposure_order=5, sensitive=False):
        self.event_id = event_id
        self.summary = summary
        self.priority = priority
        self.score = score
        self.status = status
        self.risk_name = risk_name
        self.category = category
        self.subjects = subjects
        self.permissions = permissions
        self.role = role
        self.binding = binding
        self.scope = scope
        self.reasons = reasons
        self.role_creation_time = role_creation_time
        self.binding_creation_time = binding_creation_time
        self.exposure_order = exposure_order
        self.sensitive = sensitive

    def to_dict(self):
        item = {
            'schema_version': EVENT_SCHEMA_VERSION,
            'event_type': 'rbac_risk',
            'event_id': self.event_id,
            'Summary': self.summary,
            'Priority': self.priority.name,
            'Score': self.score,
            'Status': self.status,
            'Risk': self.risk_name,
            'Category': self.category,
            'Granted To': list(self.subjects),
            'Permission': list(self.permissions),
            'Role': self.role,
            'Binding': self.binding,
            'Scope': self.scope,
            'Why': list(self.reasons),
        }
        role_created = _creation_time(self.role_creation_time)
        binding_created = _creation_time(self.binding_creation_time)
        if role_created is not None:
            item['Role Creation Time'] = role_created
        if binding_created is not None:
            item['Binding Creation Time'] = binding_created
        return item

    @property
    def sort_key(self):
        # Python sorts ascending, hence the negative priority. Active grants are
        # reviewed before latent definitions at the same priority.
        status_order = 0 if self.status == STATUS_ACTIVE else 1
        if self.scope == 'cluster-wide':
            scope_order = 0
        elif self.sensitive:
            scope_order = 1
        else:
            scope_order = 2
        return (-self.priority.value, status_order, scope_order, self.exposure_order,
                self.summary.lower(), self.event_id)


def _event_from_finding(role, binding, finding):
    scope = _scope_for(role, binding)
    status = STATUS_ACTIVE if binding is not None and binding.subjects else STATUS_LATENT
    subjects = _dedupe([
        _subject_display(subject, binding.namespace if binding else None)
        for subject in ((binding.subjects if binding else None) or [])
    ])

    capability = _capability_from_matches(finding)
    if binding is None:
        summary = 'Unbound {0} can {1}'.format(_role_display(role), capability)
    elif not subjects:
        summary = '{0} grants {1}, but has no subjects'.format(
            _binding_display(binding), capability)
    else:
        summary = '{0} can {1}{2}'.format(
            _subject_summary(binding.subjects, binding.namespace),
            capability,
            _scope_suffix(scope))

    reasons = []
    description = finding.pattern.description
    impact = finding.pattern.impact
    if description:
        reasons.append(_sentence(description))
    else:
        reasons.append('Matched risk pattern {0}.'.format(finding.pattern_name))
        impact = impact or _CATEGORY_IMPACT.get(finding.category)
    if impact:
        reasons.append(_sentence(impact))
    reasons.extend(_sentence(modifier.explanation)
                   for modifier in finding.modifiers)
    if binding is not None and not binding.subjects:
        reasons.append('The binding has no subjects, so nobody currently receives the grant.')
    reasons = _dedupe(reasons)

    return RiskEvent(
        event_id=_stable_event_id(finding, role, binding),
        summary=summary,
        priority=finding.priority,
        score=finding.score,
        status=status,
        risk_name=finding.pattern_name,
        category=finding.category,
        subjects=subjects,
        permissions=finding.match_details,
        role=_role_display(role),
        binding=_binding_display(binding),
        scope=scope,
        reasons=reasons,
        role_creation_time=role.time,
        binding_creation_time=getattr(binding, 'time', None),
        exposure_order=_exposure_order(binding.subjects if binding else None),
        sensitive=any(modifier.name == 'sensitiveNamespace'
                      for modifier in finding.modifiers),
    )


def _include_by_default(role, binding):
    """Hide only Kubernetes' own system role + system binding pairs.

    A custom binding to a system role is a deliberate grant and must stay
    visible; filtering every ``system:*`` role would hide it.
    """
    role_is_system = role.name.startswith('system:')
    if not role_is_system:
        return True
    if binding is None:
        return False
    return not binding.name.startswith('system:')


def build_risk_events(risky_roles, ctx, include_system=False):
    """Build and sort one event per finding and concrete binding."""
    events = []
    for role in risky_roles:
        bindings = ctx.bindings_for(role)
        if not bindings:
            if include_system or _include_by_default(role, None):
                findings = score_findings_for_scope(role.findings, role, ctx,
                                                     second_pass=True)
                for finding in findings:
                    events.append(_event_from_finding(role, None, finding))
            continue

        for binding in bindings:
            if not include_system and not _include_by_default(role, binding):
                continue
            scoped = (ctx.scoped_to(binding) if binding.subjects
                      else ctx.without_bindings())
            findings = score_findings_for_scope(role.findings, role, scoped,
                                                 second_pass=True)
            for finding in findings:
                events.append(_event_from_finding(role, binding, finding))

    return sorted(events, key=lambda event: event.sort_key)
