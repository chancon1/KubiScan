"""Contract tests for the grant-centred risk event model."""

import datetime
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.finding import Finding  # noqa: E402
from engine.priority import Priority  # noqa: E402
from engine.risk_event import (EVENT_BYTE_BUDGET, STATUS_ACTIVE,  # noqa: E402
                               STATUS_LATENT, build_risk_events)
from engine.role import Role  # noqa: E402
from engine.scan_context import BoundBinding, RoleFacts, ScanContext  # noqa: E402
from engine.scoring import score_finding  # noqa: E402
from engine.utils import are_rules_contain_other_rules  # noqa: E402
from engine.utils import reset_scan_cache, scan_roles_and_clusterroles  # noqa: E402
from misc.constants import (CLUSTER_ROLE_BINDING_KIND, CLUSTER_ROLE_KIND,  # noqa: E402
                            ROLE_BINDING_KIND)
from api.client_factory import ApiClientFactory  # noqa: E402
from api.config import set_api_client  # noqa: E402
from static_risky_roles import STATIC_RISKY_ROLES  # noqa: E402
from tests.helpers import Subject, rule  # noqa: E402


def role_with(name, rules):
    findings = []
    for pattern in STATIC_RISKY_ROLES:
        matches = are_rules_contain_other_rules(rules, pattern.rules)
        if matches:
            findings.append(Finding(pattern, matches))
    return Role(name, Priority.NONE, rules=rules, kind=CLUSTER_ROLE_KIND,
                findings=findings, time=datetime.datetime(2026, 1, 2, 3, 4, 5))


def secret_reader(name='secret-reader'):
    rules = [rule([''], ['secrets'], ['get', 'list', 'watch'])]
    pattern = next(p for p in STATIC_RISKY_ROLES if p.name == 'risky-secrets-read')
    finding = Finding(pattern, are_rules_contain_other_rules(rules, pattern.rules))
    return Role(name, Priority.NONE, rules=rules, kind=CLUSTER_ROLE_KIND,
                findings=[finding], time=datetime.datetime(2026, 1, 2, 3, 4, 5))


def many_risks(name='operator'):
    return role_with(name, [rule([''], ['secrets'], ['get', 'list', 'watch']),
                            rule([''], ['secrets'], ['create', 'update']),
                            rule([''], ['pods'], ['create']),
                            rule([''], ['configmaps'], ['get', 'list'])])


def event_context(role, bindings):
    ctx = ScanContext([], [], sensitive_namespaces=set(['kube-system']))
    ctx._index = {(CLUSTER_ROLE_KIND, role.name, None): list(bindings)}
    ctx.privileged_sa_known = True
    return ctx


def sa(name, namespace):
    return Subject('ServiceAccount', name, namespace)


def test_grants_with_different_reach_stay_apart(report):
    role = secret_reader()
    crb = BoundBinding(CLUSTER_ROLE_BINDING_KIND, 'global-reader', None,
                       [sa('auditor', 'security')],
                       datetime.datetime(2026, 2, 3, 4, 5, 6))
    rb = BoundBinding(ROLE_BINDING_KIND, 'team-reader', 'team-a',
                      [sa('application', 'team-a')])

    events = build_risk_events([role], event_context(role, [crb, rb]))
    by_scope = {event.scope: event for event in events}

    report('a cluster-wide and a namespaced grant are two events', len(events) == 2,
           'got {0}'.format([e.scope for e in events]))
    wide = by_scope.get('cluster-wide')
    team = by_scope.get('namespace team-a')
    report('the ClusterRoleBinding grant is scored cluster-wide',
           wide is not None and wide.priority == Priority.CRITICAL
           and wide.status == STATUS_ACTIVE, str(by_scope.keys()))
    report('the RoleBinding grant keeps its namespaced score',
           team is not None and team.priority == Priority.HIGH, str(by_scope.keys()))
    report('the event names the role the way the old report did',
           wide.to_dict()['Kind'] == 'ClusterRole'
           and wide.to_dict()['Name'] == 'secret-reader'
           and wide.to_dict()['Namespace'] is None, str(wide.to_dict()))
    report('the subject line says who holds it and through what',
           wide.subject_lines ==
           ['auditor@security [SA NS] (via ClusterRoleBinding: global-reader)'],
           str(wide.subject_lines))


def test_identical_grants_become_one_event(report):
    """Five hundred RoleBindings that score alike are one review decision."""
    role = secret_reader()
    bindings = [BoundBinding(ROLE_BINDING_KIND, 'rb-%03d' % i, 'team-%03d' % i,
                             [sa('app-%03d' % i, 'team-%03d' % i)])
                for i in range(500)]
    events = build_risk_events([role], event_context(role, bindings))

    report('five hundred identical grants collapse into one event',
           len(events) == 1, 'got {0} events'.format(len(events)))
    if not events:
        return
    event = events[0]
    item = event.to_dict()
    report('the count reports every grant, not just the listed ones',
           '500 subjects' in item['Grant Count'] and '500 bindings' in item['Grant Count'],
           item['Grant Count'])
    report('the scope says how far the group reaches',
           item['Scope'] == '500 namespaces, all via RoleBinding', item['Scope'])
    report('the subject list is capped to keep the line parsable',
           0 < len(item['Bound Service Accounts']) < 500,
           'listed {0}'.format(len(item['Bound Service Accounts'])))
    report('the event says the list was shortened',
           item['Bound Service Accounts Shown'].endswith(' of 500'),
           item.get('Bound Service Accounts Shown'))
    report('the event fits the byte budget',
           len(json.dumps(item)) <= EVENT_BYTE_BUDGET + 512,
           '{0} bytes'.format(len(json.dumps(item))))


def test_sensitive_namespace_and_cluster_binding_split_off(report):
    """The grants worth looking at must not hide inside the bulk."""
    role = secret_reader()
    bindings = [BoundBinding(ROLE_BINDING_KIND, 'rb-%02d' % i, 'team-%02d' % i,
                             [sa('app', 'team-%02d' % i)]) for i in range(20)]
    bindings.append(BoundBinding(ROLE_BINDING_KIND, 'rb-ks', 'kube-system',
                                 [sa('app', 'kube-system')]))
    bindings.append(BoundBinding(CLUSTER_ROLE_BINDING_KIND, 'crb', None,
                                 [sa('platform', 'ops')]))
    events = build_risk_events([role], event_context(role, bindings))
    scopes = sorted(e.scope for e in events)

    report('bulk, sensitive namespace and cluster binding are three events',
           len(events) == 3, 'got {0}'.format(scopes))
    report('the sensitive namespace keeps its own event',
           'namespace kube-system' in scopes, str(scopes))
    report('the ClusterRoleBinding keeps its own event',
           'cluster-wide' in scopes, str(scopes))
    report('the twenty ordinary namespaces are one event',
           '20 namespaces, all via RoleBinding' in scopes, str(scopes))


def test_several_cluster_bindings_group(report):
    """Which binding made a grant cluster-wide changes nothing about the risk.

    The modifier's rendered sentence names it, so grouping on that sentence kept
    three identical ClusterRoleBindings apart. Grouping is on what the modifier
    actually distinguishes, which for clusterWide is nothing.
    """
    role = secret_reader()
    bindings = [BoundBinding(CLUSTER_ROLE_BINDING_KIND, 'crb-%d' % i, None,
                             [sa('reader-%d' % i, 'team')]) for i in range(3)]
    events = build_risk_events([role], event_context(role, bindings))

    report('three identical ClusterRoleBindings are one event',
           len(events) == 1, 'got {0}'.format(len(events)))
    if not events:
        return
    item = events[0].to_dict()
    report('all three subjects are listed',
           len(item['Bound Service Accounts']) == 3, str(item['Bound Service Accounts']))
    report('the reason counts the bindings instead of naming one',
           any('3 ClusterRoleBindings' in r for r in item['Why']), str(item['Why']))

    # A sensitive namespace still differentiates, because its detail differs.
    mixed = [BoundBinding(ROLE_BINDING_KIND, 'rb-a', 'team-a', [sa('a', 'team-a')]),
             BoundBinding(ROLE_BINDING_KIND, 'rb-k', 'kube-system', [sa('k', 'kube-system')])]
    report('a sensitive namespace is still its own event',
           len(build_risk_events([role], event_context(role, mixed))) == 2,
           'got {0}'.format(len(build_risk_events([role], event_context(role, mixed)))))


def test_event_id_survives_a_new_member(report):
    """Adding an account is the same risk with a bigger count, not a new event."""
    role = secret_reader()
    base = [BoundBinding(ROLE_BINDING_KIND, 'rb-%02d' % i, 'team-%02d' % i,
                         [sa('app', 'team-%02d' % i)]) for i in range(5)]
    grown = base + [BoundBinding(ROLE_BINDING_KIND, 'rb-99', 'team-99',
                                 [sa('app', 'team-99')])]
    before = build_risk_events([role], event_context(role, base))[0]
    after = build_risk_events([role], event_context(role, grown))[0]

    report('the event id is unchanged when a member is added',
           before.event_id == after.event_id,
           '{0} != {1}'.format(before.event_id[:12], after.event_id[:12]))
    report('the count moves instead',
           before.to_dict()['Grant Count'] != after.to_dict()['Grant Count'],
           after.to_dict()['Grant Count'])
    report('a different verdict still gets a different id',
           build_risk_events([role], event_context(role, [
               BoundBinding(CLUSTER_ROLE_BINDING_KIND, 'crb', None,
                            [sa('a', 'b')])]))[0].event_id != before.event_id,
           'ids collided')


def test_risk_field_is_searchable(report):
    role = many_risks()
    binding = BoundBinding(CLUSTER_ROLE_BINDING_KIND, 'operator', None,
                           [sa('operator', 'ops')])
    item = build_risk_events([role], event_context(role, [binding]))[0].to_dict()

    report('RISK is one value per finding, not a wrapped block',
           isinstance(item['RISK'], list)
           and len(item['RISK']) == item['Risk Count']
           and not any('\n' in entry for entry in item['RISK']),
           str(item['RISK'][:2]))
    report('every RISK entry carries severity, name and permission',
           all(entry.split()[0] in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
               and 'risky-' in entry and ': ' in entry for entry in item['RISK']),
           str(item['RISK'][:2]))
    report('RISK is ordered strongest first',
           [Priority[e.split()[0]].value for e in item['RISK']] ==
           sorted((Priority[e.split()[0]].value for e in item['RISK']), reverse=True),
           str([e.split()[0] for e in item['RISK']]))


def test_severity_and_priority_are_separate(report):
    """Reach changes what to review first, never what the permission can do."""
    role = secret_reader()
    wide = build_risk_events([role], event_context(role, [BoundBinding(
        CLUSTER_ROLE_BINDING_KIND, 'everywhere', None, [sa('a', 'ops')])]))[0]
    narrow = build_risk_events([role], event_context(role, [BoundBinding(
        ROLE_BINDING_KIND, 'here', 'team-a', [sa('a', 'team-a')])]))[0]

    report('the same permission has the same severity wherever it is bound',
           wide.severity == narrow.severity == Priority.HIGH,
           '{0} vs {1}'.format(wide.severity.name, narrow.severity.name))
    report('reach raises review priority without touching severity',
           wide.priority == Priority.CRITICAL and narrow.priority == Priority.HIGH,
           '{0} vs {1}'.format(wide.priority.name, narrow.priority.name))

    pinned = role_with('pinned', [rule([''], ['secrets'], ['get'], resource_names=['one'])])
    event = build_risk_events([pinned], event_context(pinned, [BoundBinding(
        CLUSTER_ROLE_BINDING_KIND, 'everywhere', None, [sa('a', 'ops')])]))[0]
    report('a narrowed capability lowers severity, not only priority',
           event.severity == Priority.MEDIUM and event.priority == Priority.HIGH,
           '{0}/{1}'.format(event.severity.name, event.priority.name))


def test_latent_events(report):
    role = secret_reader()
    events = build_risk_events([role], event_context(role, []))
    event = events[0]
    report('unbound role produces one latent event',
           len(events) == 1 and event.status == STATUS_LATENT
           and not event.subject_lines, str(event.to_dict()))
    report('unbound event keeps the scorer downgrade',
           event.priority == Priority.MEDIUM, event.priority.name)

    empty = BoundBinding(CLUSTER_ROLE_BINDING_KIND, 'empty', None, [])
    empty_ctx = event_context(role, [empty])
    empty_event = build_risk_events([role], empty_ctx)[0]
    report('binding without subjects is latent rather than active',
           empty_event.status == STATUS_LATENT
           and empty_event.priority == Priority.MEDIUM
           and 'if subjects are added' in empty_event.scope,
           str(empty_event.to_dict()))

    # The role report and the event report read the same cluster, so they must
    # not disagree about it.
    role_level = score_finding(role.findings[0], role, empty_ctx, second_pass=True)
    report('the role report agrees with the event on an empty binding',
           role_level == empty_event.priority,
           'role {0}, event {1}'.format(role_level.name, empty_event.priority.name))
    why = ' '.join(empty_event.reasons).lower()
    report('the reason says the binding is empty, not that none exists',
           'has no subjects' in why and 'no rolebinding or clusterrolebinding' not in why,
           why)


def test_system_filter_keeps_deliberate_grants(report):
    role = secret_reader('system:secret-reader')
    built_in = BoundBinding(CLUSTER_ROLE_BINDING_KIND, 'system:built-in', None,
                            [Subject('Group', 'system:authenticated')])
    custom = BoundBinding(CLUSTER_ROLE_BINDING_KIND, 'custom-grant', None,
                          [Subject('User', 'alice')])
    ctx = event_context(role, [built_in, custom])
    default_events = build_risk_events([role], ctx)
    all_events = build_risk_events([role], ctx, include_system=True)
    report('default filter hides only system role plus system binding',
           len(default_events) == 1
           and 'alice' in ' '.join(default_events[0].subject_lines),
           str([e.subject_lines for e in default_events]))
    report('--include-system restores the built-in grant',
           sum(len(e.subject_lines) for e in all_events) == 2,
           str([e.subject_lines for e in all_events]))


def test_structured_contract(report):
    role = secret_reader()
    binding = BoundBinding(CLUSTER_ROLE_BINDING_KIND, 'global-reader', None,
                           [Subject('Group', 'system:authenticated'),
                            sa('auditor', 'security')])
    event = build_risk_events([role], event_context(role, [binding]))[0]
    item = event.to_dict()

    report('JSON contract preserves multivalue fields as arrays',
           isinstance(item['Bound Service Accounts'], list)
           and isinstance(item['RISK'], list)
           and isinstance(item['Why'], list), str(item))
    report('everyone binding gets a human summary',
           item['Summary'].startswith('All authenticated users can '), item['Summary'])
    report('machine schema fields remain present',
           item['schema_version'] == 4 and item['event_type'] == 'rbac_grant'
           and item['Risk Count'] == 1 and item['Priority'] == 'CRITICAL'
           and item['Severity'] == 'HIGH', str(item))
    strings = [item['Summary'], item['Scope'], item['Grant Count']]
    strings += item['Bound Service Accounts'] + item['RISK'] + item['Why']
    report('human event fields remain ASCII for the log pipeline',
           not [v for v in strings if any(ord(c) > 127 for c in v)], str(strings))


def test_review_order_prefers_broad_exposure(report):
    role = secret_reader()
    account = BoundBinding(CLUSTER_ROLE_BINDING_KIND, 'single-account', None,
                           [sa('auditor', 'security')])
    everyone = BoundBinding(CLUSTER_ROLE_BINDING_KIND, 'all-users', None,
                            [Subject('Group', 'system:authenticated')])
    events = build_risk_events([role], event_context(role, [account, everyone]))
    report('broad group sorts before one service account',
           len(events) == 2
           and 'system:authenticated' in ' '.join(events[0].subject_lines),
           str([e.subject_lines for e in events]))


def aggregated_context(parent, source, source_bindings=()):
    ctx = ScanContext([], [], sensitive_namespaces=set())
    parent_key = (CLUSTER_ROLE_KIND, parent.name, None)
    source_key = (CLUSTER_ROLE_KIND, source.name, None)
    ctx._roles_by_key = {
        parent_key: RoleFacts(parent.rules, {}, [
            {'labels': {'aggregate-to-parent': 'true'}, 'expressions': []}]),
        source_key: RoleFacts(source.rules, {'aggregate-to-parent': 'true'}, []),
    }
    ctx._index = {
        parent_key: [BoundBinding(CLUSTER_ROLE_BINDING_KIND, 'parent-binding', None,
                                  [sa('controller', 'ops')])],
        source_key: list(source_bindings),
    }
    ctx.privileged_sa_known = True
    return ctx


def test_aggregated_source_becomes_evidence(report):
    parent = secret_reader('parent')
    source = secret_reader('source')
    events = build_risk_events([parent, source], aggregated_context(parent, source))
    report('an unbound aggregation source is not a second event',
           len(events) == 1 and events[0].role.name == 'parent',
           str([e.role.name for e in events]))
    if not events:
        return
    report('the parent names where its rules came from',
           events[0].to_dict().get('Aggregated From') == ['ClusterRole source'],
           str(events[0].to_dict().get('Aggregated From')))
    report('the fold is explained rather than silent',
           any('aggregated from' in r.lower() for r in events[0].reasons),
           str(events[0].reasons))


def test_bound_aggregation_source_keeps_its_event(report):
    parent = secret_reader('parent')
    source = secret_reader('source')
    own = BoundBinding(CLUSTER_ROLE_BINDING_KIND, 'source-binding', None,
                       [Subject('User', 'alice')])
    events = build_risk_events([parent, source], aggregated_context(parent, source, [own]))
    report('a bound aggregation source keeps its own event',
           sorted(e.role.name for e in events) == ['parent', 'source'],
           str([e.role.name for e in events]))


def test_static_scan_and_json_export(report):
    """Exercise the same scan -> events -> JSON path the Job uses."""
    fixture = os.path.join(os.path.dirname(__file__), 'fixtures', 'risk_events.yaml')
    set_api_client(ApiClientFactory.get_client(use_static=True, input_file=fixture))
    reset_scan_cache()
    risky_roles, ctx = scan_roles_and_clusterroles(force=True)
    events = build_risk_events(risky_roles, ctx)

    report('static scan builds grant-centred events',
           len(events) == 3
           and [e.priority.name for e in events] == ['CRITICAL', 'HIGH', 'HIGH'],
           str([(e.priority.name, e.summary) for e in events]))

    import KubiScan
    descriptor, path = tempfile.mkstemp(prefix='kubiscan-events-', suffix='.json')
    os.close(descriptor)
    try:
        KubiScan.export_risk_events_to_json(events, path)
        with open(path, 'r') as stream:
            payload = json.load(stream)
    finally:
        os.remove(path)
    items = payload[0]['RBAC Risk Events']
    report('structured exporter writes one section and one object per event',
           len(payload) == 1 and len(items) == len(events), str(payload))
    report('export keeps arrays and scan metadata intact',
           isinstance(items[0]['Bound Service Accounts'], list)
           and isinstance(items[0]['RISK'], list)
           and items[0]['scan_tool'] == 'kubiscan'
           and 'scan_timestamp' in items[0]
           and 'Cluster Name' not in items[0], str(items[0]))
    # A constant on every line is not metadata, it is padding. 'section' told
    # the legacy report's sections apart and there is only one here; 'Review
    # Order' was a sorted table's row number, which churns between scans as
    # unrelated roles come and go.
    report('the export carries no constant or churning padding',
           'section' not in items[0] and 'Review Order' not in items[0],
           str(sorted(items[0])))


TESTS = [test_grants_with_different_reach_stay_apart,
         test_identical_grants_become_one_event,
         test_several_cluster_bindings_group,
         test_sensitive_namespace_and_cluster_binding_split_off,
         test_event_id_survives_a_new_member,
         test_risk_field_is_searchable,
         test_severity_and_priority_are_separate,
         test_latent_events,
         test_system_filter_keeps_deliberate_grants,
         test_structured_contract,
         test_review_order_prefers_broad_exposure,
         test_aggregated_source_becomes_evidence,
         test_bound_aggregation_source_keeps_its_event,
         test_static_scan_and_json_export]
