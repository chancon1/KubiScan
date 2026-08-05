"""Contract tests for the binding-centred Splunk event model."""

import datetime
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.finding import Finding  # noqa: E402
from engine.priority import Priority  # noqa: E402
from engine.risk_event import (STATUS_ACTIVE, STATUS_LATENT,  # noqa: E402
                               build_risk_events)
from engine.role import Role  # noqa: E402
from engine.scan_context import BoundBinding, ScanContext  # noqa: E402
from engine.utils import are_rules_contain_other_rules  # noqa: E402
from engine.utils import reset_scan_cache, scan_roles_and_clusterroles  # noqa: E402
from misc.constants import (CLUSTER_ROLE_BINDING_KIND, CLUSTER_ROLE_KIND,  # noqa: E402
                            ROLE_BINDING_KIND)
from api.client_factory import ApiClientFactory  # noqa: E402
from api.config import set_api_client  # noqa: E402
from static_risky_roles import STATIC_RISKY_ROLES  # noqa: E402
from tests.helpers import Subject, rule  # noqa: E402


def secret_reader(name='secret-reader'):
    rules = [rule([''], ['secrets'], ['get', 'list', 'watch'])]
    pattern = next(pattern for pattern in STATIC_RISKY_ROLES
                   if pattern.name == 'risky-secrets-read')
    finding = Finding(pattern, are_rules_contain_other_rules(rules, pattern.rules))
    return Role(name, Priority.NONE, rules=rules, kind=CLUSTER_ROLE_KIND,
                findings=[finding], time=datetime.datetime(2026, 1, 2, 3, 4, 5))


def event_context(role, bindings):
    ctx = ScanContext([], [], sensitive_namespaces=set(['kube-system']))
    ctx._index = {(CLUSTER_ROLE_KIND, role.name, None): list(bindings)}
    ctx.privileged_sa_known = True
    return ctx


def test_one_event_per_binding_and_finding(report):
    role = secret_reader()
    crb = BoundBinding(
        CLUSTER_ROLE_BINDING_KIND, 'global-reader', None,
        [Subject('ServiceAccount', 'auditor', 'security')],
        datetime.datetime(2026, 2, 3, 4, 5, 6))
    rb = BoundBinding(
        ROLE_BINDING_KIND, 'team-reader', 'team-a',
        [Subject('ServiceAccount', 'application', 'team-a')])

    events = build_risk_events([role], event_context(role, [crb, rb]))
    by_binding = {event.binding: event for event in events}

    global_event = by_binding['ClusterRoleBinding global-reader']
    team_event = by_binding['RoleBinding team-a/team-reader']
    report('one finding with two bindings becomes two events', len(events) == 2,
           'got {0}'.format(len(events)))
    report('ClusterRoleBinding event is scored cluster-wide',
           global_event.priority == Priority.CRITICAL
           and global_event.scope == 'cluster-wide'
           and global_event.status == STATUS_ACTIVE,
           str(global_event.to_dict()))
    report('RoleBinding event keeps its namespaced score',
           team_event.priority == Priority.HIGH
           and team_event.scope == 'namespace team-a'
           and team_event.status == STATUS_ACTIVE,
           str(team_event.to_dict()))
    report('events contain only the permission that matched',
           global_event.permissions == ['[core] secrets: get,list,watch'],
           str(global_event.permissions))
    report('event summary names the subject, capability and reach',
           global_event.summary ==
           'ServiceAccount security/auditor can read Kubernetes Secrets cluster-wide',
           global_event.summary)
    report('binding creation time is preserved',
           global_event.to_dict().get('Binding Creation Time') ==
           '2026-02-03T04:05:06Z', str(global_event.to_dict()))


def test_binding_reasons_are_isolated(report):
    role = secret_reader()
    crb = BoundBinding(CLUSTER_ROLE_BINDING_KIND, 'global-reader', None,
                       [Subject('ServiceAccount', 'auditor', 'security')])
    rb = BoundBinding(ROLE_BINDING_KIND, 'team-reader', 'team-a',
                      [Subject('ServiceAccount', 'application', 'team-a')])
    events = build_risk_events([role], event_context(role, [crb, rb]))
    by_binding = {event.binding: event for event in events}

    global_why = ' '.join(by_binding['ClusterRoleBinding global-reader'].reasons)
    team_why = ' '.join(by_binding['RoleBinding team-a/team-reader'].reasons)
    report('cluster-wide reason names only the guilty binding',
           'global-reader' in global_why and 'team-reader' not in global_why,
           global_why)
    report('namespaced event does not inherit cluster-wide reasoning',
           'cluster-wide' not in team_why.lower(), team_why)


def test_latent_events(report):
    role = secret_reader()
    ctx = event_context(role, [])
    events = build_risk_events([role], ctx)
    event = events[0]
    report('unbound role produces one latent event',
           len(events) == 1 and event.status == STATUS_LATENT
           and event.binding == 'none', str(event.to_dict()))
    report('unbound event keeps the scorer downgrade',
           event.priority == Priority.MEDIUM, event.priority.name)

    empty = BoundBinding(CLUSTER_ROLE_BINDING_KIND, 'empty', None, [])
    empty_event = build_risk_events([role], event_context(role, [empty]))[0]
    report('binding without subjects is latent rather than active',
           empty_event.status == STATUS_LATENT
           and empty_event.priority == Priority.MEDIUM
           and 'if subjects are added' in empty_event.scope,
           str(empty_event.to_dict()))


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
           and default_events[0].binding == 'ClusterRoleBinding custom-grant',
           str([event.binding for event in default_events]))
    report('--include-system restores built-in event', len(all_events) == 2,
           str([event.binding for event in all_events]))


def test_structured_contract_and_stable_id(report):
    role = secret_reader()
    binding = BoundBinding(CLUSTER_ROLE_BINDING_KIND, 'global-reader', None,
                           [Subject('Group', 'system:authenticated'),
                            Subject('ServiceAccount', 'auditor', 'security')])
    ctx = event_context(role, [binding])
    first = build_risk_events([role], ctx)[0]
    second = build_risk_events([role], ctx)[0]
    other_binding = BoundBinding(CLUSTER_ROLE_BINDING_KIND, 'another-reader', None,
                                 [Subject('Group', 'system:authenticated')])
    other_grant = build_risk_events([role], event_context(role, [other_binding]))[0]
    item = first.to_dict()

    report('event id is stable for the same RBAC grant', first.event_id == second.event_id,
           first.event_id + ' != ' + second.event_id)
    report('event id distinguishes different RBAC grants', first.event_id != other_grant.event_id,
           first.event_id)
    report('JSON contract preserves multivalue fields as arrays',
           isinstance(item['Granted To'], list)
           and isinstance(item['Permission'], list)
           and isinstance(item['Why'], list), str(item))
    report('everyone binding gets a human summary',
           first.summary.startswith('All authenticated users can '), first.summary)
    report('machine schema fields remain present',
           item['schema_version'] == 2 and item['event_type'] == 'rbac_risk'
           and item['Risk'] == 'risky-secrets-read'
           and item['Score'] == 'HIGH -> CRITICAL', str(item))
    strings = [first.summary, first.role, first.binding, first.scope]
    strings += first.subjects + first.permissions + first.reasons
    report('human event fields remain ASCII for the log pipeline',
           not [value for value in strings if any(ord(char) > 127 for char in value)],
           str(strings))


def test_review_order_prefers_broad_exposure(report):
    role = secret_reader()
    service_account = BoundBinding(
        CLUSTER_ROLE_BINDING_KIND, 'single-account', None,
        [Subject('ServiceAccount', 'auditor', 'security')])
    everyone = BoundBinding(
        CLUSTER_ROLE_BINDING_KIND, 'all-users', None,
        [Subject('Group', 'system:authenticated')])
    events = build_risk_events([role], event_context(role, [service_account, everyone]))
    report('broad group sorts before one service account at the same severity',
           [event.binding for event in events] ==
           ['ClusterRoleBinding all-users', 'ClusterRoleBinding single-account'],
           str([event.binding for event in events]))


def test_static_scan_and_json_export(report):
    """Exercise the same scan -> events -> JSON path the Job uses."""
    fixture = os.path.join(os.path.dirname(__file__), 'fixtures', 'risk_events.yaml')
    set_api_client(ApiClientFactory.get_client(use_static=True, input_file=fixture))
    reset_scan_cache()
    risky_roles, ctx = scan_roles_and_clusterroles(force=True)
    events = build_risk_events(risky_roles, ctx)

    report('static scan builds binding-centred events',
           len(events) == 3
           and [event.priority.name for event in events] ==
           ['CRITICAL', 'HIGH', 'HIGH'],
           str([(event.priority.name, event.summary) for event in events]))

    # Importing the CLI module is safe (main is guarded) and keeps the export
    # contract under the same no-cluster test runner as the analysis itself.
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
           isinstance(items[0]['Granted To'], list)
           and isinstance(items[0]['Why'], list)
           and 'Cluster Name' not in items[0]
           and items[0]['Review Order'] == 1
           and items[0]['section'] == 'RBAC Risk Events', str(items[0]))


TESTS = [test_one_event_per_binding_and_finding,
         test_binding_reasons_are_isolated,
         test_latent_events,
         test_system_filter_keeps_deliberate_grants,
         test_structured_contract_and_stable_id,
         test_review_order_prefers_broad_exposure,
         test_static_scan_and_json_export]
