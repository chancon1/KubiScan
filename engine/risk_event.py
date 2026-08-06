"""Turn scored RBAC findings into compact, structured risk events.

The unit of a schema-v4 event is one **distinct risk verdict**:

    one role, one way of being granted, and everybody who holds it that way

Earlier schemas emitted one event per matched pattern and binding. On a real
cluster that turned 59 risky roles into 471 records, and a ClusterRole handed to
five hundred accounts through five hundred RoleBindings produced five hundred
copies of the same review decision. Nothing there was wrong; it was just not
reviewable.

Grants that score identically are therefore one event, counted rather than
repeated. What splits an event out is a *different verdict*, which is exactly
the set worth looking at: a ClusterRoleBinding among the RoleBindings, or a
grant that landed in a sensitive namespace. No rule says so - a grant scored
differently reads differently, and so groups separately.

Three things follow.

*Identity.* The event id is derived from the role and the verdict, never from
the members. Adding a service account has to read as the same risk with a bigger
count, not as a brand new event on every scan.

*Size.* The subject list is fitted to a byte budget rather than to a fixed
number of names, because the same sixty accounts fit beside a role with eighteen
findings and overflow beside one with sixty-four. Whatever does not fit is
reported as a count.

*Two scores.* ``Severity`` is the strongest attack path the grant contains -
what it lets you do. ``Priority`` is what to review first, which additionally
weighs where the grant lands and who holds it. Neither is a count: twenty risky
permissions are not worse than the worst of them.

Kubernetes fills an aggregated ClusterRole's rules from every ClusterRole
matching its selectors, so those permissions would otherwise be reported twice:
once on the bound parent, once on each source as a latent definition. The
sources are folded into the parent as ``Aggregated From``.

A chain that no single role explains cannot be keyed on a role at all, so it
keeps its own event type, keyed on the subject that completes it.

This module is a presentation layer over the existing matcher and scorer. It
does not mutate the Role objects the legacy reports use.
"""

import hashlib
import json
import os

from engine.priority import Priority
from engine.scoring import (highest_priority, highest_severity,
                            score_findings_for_scope)
from engine.subject_chain import build_subject_chains
from misc.constants import (CLUSTER_ROLE_BINDING_KIND, CLUSTER_ROLE_KIND,
                            GROUP_KIND, ROLE_KIND, SERVICEACCOUNT_KIND)


STATUS_ACTIVE = 'ACTIVE'
STATUS_LATENT = 'LATENT'
EVENT_SCHEMA_VERSION = 4

EVENT_TYPE_GRANT = 'rbac_grant'
EVENT_TYPE_CHAIN = 'rbac_chain'

MAX_REASONS_SHOWN = 3

# How large one event may get before the subject list stops growing. Splunk
# truncates a line at 10000 bytes by default and cuts the tail, which would
# leave invalid JSON rather than a shortened list, so the list is fitted to a
# budget with headroom instead.
#
# Set KUBISCAN_EVENT_BYTE_BUDGET alongside the collector's own limit and the
# list grows to match: the cap is a byte budget rather than a number of
# accounts, because the same sixty accounts fit beside a role with eighteen
# findings and overflow beside one with sixty-four.
DEFAULT_EVENT_BYTE_BUDGET = 8000


def _configured_budget():
    raw = os.environ.get('KUBISCAN_EVENT_BYTE_BUDGET')
    if not raw:
        return DEFAULT_EVENT_BYTE_BUDGET
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_EVENT_BYTE_BUDGET
    return value if value > 0 else DEFAULT_EVENT_BYTE_BUDGET


EVENT_BYTE_BUDGET = _configured_budget()


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




def _stable_event_id(parts):
    raw = '\x1f'.join(part or '' for part in parts).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


# How directly a category leads to taking the cluster over. Used only to pick
# which of several equally severe findings gets to name the event, so that a
# grant able to exec into containers does not get headlined by whichever risk
# happens to sort first alphabetically.
_CATEGORY_RANK = {
    'privilege-escalation': 0,
    'credential-access': 1,
    'control-plane': 2,
    'workload-execution': 3,
    'policy-bypass': 4,
    'data-access': 5,
    'network': 6,
    'availability': 7,
    'observability': 8,
    'recon': 9,
}


def _finding_rank(finding):
    """Strongest first, and among equals the one that explains itself best."""
    return (-finding.severity.value,
            -finding.priority.value,
            _CATEGORY_RANK.get(finding.category, 99),
            0 if finding.pattern.summary else 1,
            finding.pattern_name)


def _risk_line(finding):
    """One RISK entry: 'HIGH  risky-pods-exec  [core] pods/exec: create'.

    Deliberately one flat string per finding rather than a nested object. The
    log collector indexes it as a multivalue field, so RISK="risky-pods-exec"
    is searchable; a wrapped text block of all findings is neither readable nor
    searchable, which is what the previous report's 'Rules' column proved.
    """
    return '{0:<8} {1:<36} {2}'.format(
        finding.severity.name, finding.pattern_name,
        '; '.join(finding.match_details))


def _grant_line(binding, subject):
    """One 'Bound Service Accounts' entry, in the report's established style."""
    if binding.kind == CLUSTER_ROLE_BINDING_KIND:
        via = 'ClusterRoleBinding: {0}'.format(binding.name)
    else:
        via = 'RoleBinding: {0}/{1}'.format(binding.namespace, binding.name)
    kind = getattr(subject, 'kind', None) or 'Subject'
    name = getattr(subject, 'name', None) or 'unknown'
    if kind == SERVICEACCOUNT_KIND:
        namespace = getattr(subject, 'namespace', None) or binding.namespace or 'unknown'
        return '{0}@{1} [SA NS] (via {2})'.format(name, namespace, via)
    return '{0} [{1}] (via {2})'.format(name, kind, via)


class Grant(object):
    """One binding through which a role reaches one or more subjects."""

    def __init__(self, role, binding, findings):
        self.role = role
        self.binding = binding
        self.findings = findings

    @property
    def subject_lines(self):
        if self.binding is None:
            return []
        return [_grant_line(self.binding, subject)
                for subject in (self.binding.subjects or [])]

    @property
    def namespace(self):
        if self.binding is None or self.binding.kind == CLUSTER_ROLE_BINDING_KIND:
            return None
        return self.binding.namespace

    @property
    def verdict(self):
        """What makes two grants of one role the same risk.

        Compared on each modifier's name and its ``detail``, never on the
        sentence it renders. The sentence names the binding it came from - three
        ClusterRoleBindings to one role produce three different strings for the
        same fact - while ``detail`` holds only what genuinely differentiates the
        grant: the sensitive namespace, the group it went to, the accounts it can
        reach. 'clusterWide' leaves it empty on purpose, because which binding
        made a grant cluster-wide changes nothing about the risk.

        The binding kind is compared separately, which is what keeps a
        ClusterRoleBinding out of a group of RoleBindings.
        """
        return (self.role.kind or '', self.role.namespace or '', self.role.name or '',
                self.binding.kind if self.binding is not None else '',
                tuple((finding.pattern_name, finding.severity.name, finding.priority.name,
                       tuple((modifier.name, modifier.detail or '')
                             for modifier in finding.modifiers))
                      for finding in self.findings))


class RiskEvent(object):
    """One reviewable RBAC risk: a role, a verdict, and everyone who holds it."""

    def __init__(self, event_type, event_id, summary, severity, priority, status,
                 role, scope, grant_count, binding_count, subject_lines,
                 subjects_total, risk_lines, reasons, aggregated_from=None,
                 role_creation_time=None, exposure_order=5, sensitive=False,
                 namespace_count=0):
        self.event_type = event_type
        self.event_id = event_id
        self.summary = summary
        self.severity = severity
        self.priority = priority
        self.status = status
        self.role = role
        self.scope = scope
        self.grant_count = grant_count
        self.binding_count = binding_count
        self.subject_lines = subject_lines
        self.subjects_total = subjects_total
        self.risk_lines = risk_lines
        self.reasons = reasons
        self.aggregated_from = aggregated_from or []
        self.role_creation_time = role_creation_time
        self.exposure_order = exposure_order
        self.sensitive = sensitive
        self.namespace_count = namespace_count

    @property
    def subjects_truncated(self):
        return self.subjects_total > len(self.subject_lines)

    def to_dict(self):
        item = {
            'schema_version': EVENT_SCHEMA_VERSION,
            'event_type': self.event_type,
            'event_id': self.event_id,
            'Summary': self.summary,
            'Priority': self.priority.name,
            'Severity': self.severity.name,
            'Status': self.status,
            'Kind': self.role.kind,
            'Name': self.role.name,
            'Namespace': self.role.namespace,
            'Scope': self.scope,
            'Grant Count': self.grant_count,
            'Bound Service Accounts': list(self.subject_lines),
            'RISK': list(self.risk_lines),
            'Risk Count': len(self.risk_lines),
            'Why': list(self.reasons),
        }
        if self.subjects_truncated:
            item['Bound Service Accounts Shown'] = '{0} of {1}'.format(
                len(self.subject_lines), self.subjects_total)
        if self.aggregated_from:
            item['Aggregated From'] = list(self.aggregated_from)
        created = _creation_time(self.role_creation_time)
        if created is not None:
            item['Creation Time'] = created
        return item

    @property
    def sort_key(self):
        # Python sorts ascending, hence the negatives. Review order is Priority
        # first - that is what it is for - with Severity breaking its ties.
        status_order = 0 if self.status == STATUS_ACTIVE else 1
        if self.scope.startswith('cluster-wide'):
            scope_order = 0
        elif self.sensitive:
            scope_order = 1
        else:
            scope_order = 2
        return (-self.priority.value, -self.severity.value, status_order, scope_order,
                self.exposure_order, self.summary.lower(), self.event_id)


def _fit_subjects(event_fields, lines, budget):
    """As many subject lines as fit the byte budget, and how many there were.

    A fixed cap cannot work: the same 60 accounts fit beside a role with 18
    findings and overflow beside one with 64, and long names halve it again.
    Filling until the event is full gives the most names the pipeline can carry,
    whatever the role looks like, and adjusts by itself if the collector's limit
    is raised.
    """
    base = len(json.dumps(dict(event_fields, **{'Bound Service Accounts': []})))
    kept = []
    for line in lines:
        base += len(json.dumps(line)) + 1
        if base > budget:
            break
        kept.append(line)
    return kept, len(lines)


def _scope_of(grants):
    """Where the whole group applies, phrased for however many members it has."""
    sample = grants[0]
    if sample.binding is None:
        if sample.role.kind == ROLE_KIND:
            return 'namespace {0} if bound'.format(sample.role.namespace)
        return 'cluster-wide if bound by a ClusterRoleBinding'
    if not any(g.binding.subjects for g in grants):
        if sample.binding.kind == CLUSTER_ROLE_BINDING_KIND:
            return 'cluster-wide if subjects are added'
        return 'namespace {0} if subjects are added'.format(sample.binding.namespace)
    if sample.binding.kind == CLUSTER_ROLE_BINDING_KIND:
        return 'cluster-wide'
    namespaces = sorted({g.namespace for g in grants if g.namespace})
    if len(namespaces) == 1:
        return 'namespace {0}'.format(namespaces[0])
    return '{0} namespaces, all via RoleBinding'.format(len(namespaces))


def _summary_of(grants, strongest, scope, subjects_total):
    capability = strongest.pattern.summary or _capability_from_matches(strongest)
    sample = grants[0]
    if sample.binding is None:
        return 'Unbound {0} can {1}'.format(_role_display(sample.role), capability)
    if not subjects_total:
        return '{0} grants {1}, but has no subjects'.format(
            _binding_display(sample.binding), capability)
    if subjects_total == 1:
        who = _subject_summary(sample.binding.subjects, sample.binding.namespace)
    else:
        everyone = [g for g in grants
                    if _exposure_order(g.binding.subjects if g.binding else None) < 2]
        if everyone:
            who = _subject_summary(everyone[0].binding.subjects, everyone[0].binding.namespace)
        else:
            who = '{0} subjects'.format(subjects_total)
    if scope.endswith('namespaces, all via RoleBinding'):
        where = ', each in its own namespace'
    else:
        where = _scope_suffix(scope)
    return '{0} can {1}{2}'.format(who, capability, where)


def _event_from_grants(grants, aggregated_from=None):
    """Fold every grant with the same verdict into one event."""
    sample = grants[0]
    findings = sorted(sample.findings, key=_finding_rank)
    strongest = findings[0]

    scope = _scope_of(grants)
    subject_lines = []
    for grant in grants:
        subject_lines.extend(grant.subject_lines)
    subject_lines = _dedupe(subject_lines)
    status = STATUS_ACTIVE if subject_lines else STATUS_LATENT

    namespaces = sorted({g.namespace for g in grants if g.namespace})
    bindings = len([g for g in grants if g.binding is not None])
    if not subject_lines:
        grant_count = 'no subjects'
    elif bindings == 1:
        grant_count = '{0} subject{1}, 1 binding'.format(
            len(subject_lines), '' if len(subject_lines) == 1 else 's')
    else:
        grant_count = '{0} subjects, {1} bindings{2}'.format(
            len(subject_lines), bindings,
            ' in {0} namespaces'.format(len(namespaces)) if namespaces else '')

    reasons = []
    if strongest.pattern.description:
        reasons.append(_sentence(strongest.pattern.description))
    else:
        reasons.append('Matched risk pattern {0}.'.format(strongest.pattern_name))
    impact = strongest.pattern.impact or _CATEGORY_IMPACT.get(strongest.category)
    if impact:
        reasons.append(_sentence(impact))
    for modifier in strongest.modifiers:
        # The stored sentence names the one binding it was scored against. Once
        # several bindings share the event, naming the first of them would read
        # as though the others were not there.
        if modifier.name == 'clusterWide' and bindings > 1:
            reasons.append('Granted cluster-wide by {0} ClusterRoleBindings.'.format(bindings))
        else:
            reasons.append(_sentence(modifier.explanation))
    reasons = _dedupe(reasons)[:MAX_REASONS_SHOWN]
    if status == STATUS_LATENT and sample.binding is not None:
        reasons.append('The binding has no subjects, so nobody currently receives the grant.')
    if aggregated_from:
        reasons.append('Rules are aggregated from {0} ClusterRole{1}, reported here '
                       'rather than separately.'.format(
                           len(aggregated_from), '' if len(aggregated_from) == 1 else 's'))

    fields = {
        'schema_version': EVENT_SCHEMA_VERSION,
        'event_type': EVENT_TYPE_GRANT,
        'event_id': 'x' * 64,
        'Summary': _summary_of(grants, strongest, scope, len(subject_lines)),
        'Priority': '', 'Severity': '', 'Status': status,
        'Kind': sample.role.kind, 'Name': sample.role.name,
        'Namespace': sample.role.namespace, 'Scope': scope,
        'Grant Count': grant_count,
        'RISK': [_risk_line(f) for f in findings],
        'Risk Count': len(findings), 'Why': reasons,
        'Aggregated From': list(aggregated_from or []),
        'Creation Time': _creation_time(sample.role.time) or '',
    }
    shown, total = _fit_subjects(fields, subject_lines, EVENT_BYTE_BUDGET)

    # Deliberately not derived from the members: adding a service account to a
    # role must read as the same risk with a bigger count, not as a brand new
    # event every scan. What changes the identity is the verdict.
    event_id = _stable_event_id([
        sample.role.kind, sample.role.namespace, sample.role.name,
        sample.binding.kind if sample.binding is not None else '',
        scope if not scope[0].isdigit() else 'grouped',
        '|'.join(fields['RISK']),
        '|'.join(reasons),
    ])

    return RiskEvent(
        event_type=EVENT_TYPE_GRANT,
        event_id=event_id,
        summary=fields['Summary'],
        severity=highest_severity(findings),
        priority=highest_priority(findings),
        status=status,
        role=sample.role,
        scope=scope,
        grant_count=grant_count,
        binding_count=bindings,
        subject_lines=shown,
        subjects_total=total,
        risk_lines=fields['RISK'],
        reasons=reasons,
        aggregated_from=aggregated_from,
        role_creation_time=sample.role.time,
        exposure_order=min(_exposure_order(g.binding.subjects if g.binding else None)
                           for g in grants),
        sensitive=any(m.name == 'sensitiveNamespace'
                      for f in findings for m in f.modifiers),
        namespace_count=len(namespaces),
    )


def _chain_event(chain):
    """One event for a chain a subject completes out of several roles.

    Shaped like the grant events around it - same fields, same sort order -
    because a reader triaging the report should not have to learn a second
    format to see that this is the same kind of problem by a different route.
    """
    finding = chain.finding
    subject = _subject_display(chain.subject, chain.identity[2])
    scope = 'cluster-wide' if chain.is_cluster_wide \
        else 'namespace {0}'.format(chain.scope.namespace)
    grants = chain.grants

    capability = finding.pattern.summary or 'combine {0} permissions'.format(
        (finding.category or 'risky').replace('-', ' '))
    summary = '{0} can {1}{2}, through {3} roles'.format(
        subject, capability, _scope_suffix(scope), len(grants))

    reasons = []
    if finding.pattern.description:
        reasons.append(_sentence(finding.pattern.description))
    else:
        reasons.append('Matched risk pattern {0}.'.format(finding.pattern_name))
    impact = finding.pattern.impact or _CATEGORY_IMPACT.get(finding.category)
    if impact:
        reasons.append(_sentence(impact))
    reasons.append('No single role grants this; the subject assembles it from '
                   '{0} separate grants.'.format(len(grants)))
    for match, suppliers in chain.legs:
        reasons.append('{0} comes from {1}.'.format(
            match.render(),
            ', '.join('{0} via {1}'.format(g.role_display, g.binding_display)
                      for g in suppliers)))
    reasons.extend(_sentence(m.explanation) for m in finding.modifiers)

    class _ChainRole(object):
        kind = 'Chain'
        name = ' + '.join(g.role_display for g in grants)
        namespace = None if chain.is_cluster_wide else chain.scope.namespace
        time = None

    return RiskEvent(
        event_type=EVENT_TYPE_CHAIN,
        event_id=_stable_event_id(
            [finding.pattern_name, chain.identity[0], chain.identity[1],
             chain.identity[2] or '', chain.scope.namespace or '']
            + sorted('{0}\x1e{1}'.format(g.role_display, g.binding_display) for g in grants)),
        summary=summary,
        severity=finding.severity,
        priority=finding.priority,
        status=STATUS_ACTIVE,
        role=_ChainRole(),
        scope=scope,
        grant_count='1 subject, {0} roles'.format(len(grants)),
        binding_count=len(grants),
        subject_lines=['{0} (via {1})'.format(subject, ', '.join(
            g.binding_display for g in grants))],
        subjects_total=1,
        risk_lines=[_risk_line(finding)],
        reasons=_dedupe(reasons),
        exposure_order=_exposure_order([chain.subject]),
        sensitive=any(m.name == 'sensitiveNamespace' for m in finding.modifiers),
    )


def _chain_is_system(chain):
    """Chains assembled entirely out of Kubernetes' own roles are built in."""
    return all(grant.is_system_role for grant in chain.grants)


def _include_by_default(role, binding):
    """Hide only Kubernetes' own system role + system binding pairs.

    A custom binding to a system role is a deliberate grant and must stay
    visible; filtering every ``system:*`` role would hide it.
    """
    if not role.name.startswith('system:'):
        return True
    if binding is None:
        return False
    return not binding.name.startswith('system:')


def _role_key(role):
    if role.kind == CLUSTER_ROLE_KIND:
        return (CLUSTER_ROLE_KIND, role.name, None)
    return (ROLE_KIND, role.name, role.namespace)


def _resolve_aggregation(risky_roles, ctx, reported):
    """(folded-away role keys, parent key -> source display names).

    A source is only folded into a parent that survives filtering. Folding it
    into a parent nobody will see would delete the finding instead of moving it,
    which is the one outcome worse than reporting it twice.
    """
    folded = set()
    sources_of = {}
    by_key = {}
    for role in risky_roles:
        by_key.setdefault(_role_key(role), role)

    for parent_key, source_keys in ctx.foldable_sources().items():
        if parent_key not in reported:
            continue
        for source_key in source_keys:
            if source_key not in by_key:
                continue
            folded.add(source_key)
            sources_of.setdefault(parent_key, []).append(
                _role_display(by_key[source_key]))
    return folded, {key: sorted(names) for key, names in sources_of.items()}


def build_risk_events(risky_roles, ctx, include_system=False):
    """One event per distinct risk verdict, however many grants share it.

    Five hundred RoleBindings to one role are five hundred copies of the same
    review decision. Folding the ones that score identically leaves the handful
    that differ - a ClusterRoleBinding, a sensitive namespace - visible on their
    own, which is exactly the set worth looking at.
    """
    events = []
    for chain in build_subject_chains(ctx):
        if include_system or not _chain_is_system(chain):
            events.append(_chain_event(chain))

    reported = set()
    for role in risky_roles:
        bindings = ctx.bindings_for(role) or [None]
        if any(include_system or _include_by_default(role, b) for b in bindings):
            reported.add(_role_key(role))
    folded, sources_of = _resolve_aggregation(risky_roles, ctx, reported)

    groups = {}
    order = []
    for role in risky_roles:
        key = _role_key(role)
        if key in folded:
            continue
        bindings = ctx.bindings_for(role)
        if not bindings:
            if not (include_system or _include_by_default(role, None)):
                continue
            candidates = [None]
        else:
            candidates = [b for b in bindings
                          if include_system or _include_by_default(role, b)]

        for binding in candidates:
            scoped = ctx if binding is None else ctx.scoped_to(binding)
            findings = score_findings_for_scope(role.findings, role, scoped,
                                                second_pass=True)
            grant = Grant(role, binding, findings)
            verdict = grant.verdict
            if verdict not in groups:
                groups[verdict] = []
                order.append(verdict)
            groups[verdict].append(grant)

    for verdict in order:
        grants = groups[verdict]
        events.append(_event_from_grants(grants, sources_of.get(_role_key(grants[0].role))))

    return sorted(events, key=lambda event: event.sort_key)
