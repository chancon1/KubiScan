"""Guards on the risky-permission matrix itself.

Three questions, in order of how badly a wrong answer hurts:

1. Did anything stop being detected? A dropped verb is silent - the scan still
   runs, the report still looks full, and the permission is simply gone.
2. Is every pattern reachable at all, on a role built from its own rules? A
   pattern shadowed by an earlier one is dead weight that reads as coverage.
3. Does a pattern stay quiet on what it does not cover?
"""
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from misc.constants import CLUSTER_ROLE_KIND, ROLE_KIND  # noqa: E402
from engine.risky_pattern import CLUSTER_SCOPE  # noqa: E402
from engine.utils import evaluate_role  # noqa: E402
from static_risky_roles import STATIC_RISKY_ROLES  # noqa: E402
from tests.helpers import (FIXTURE, RawRole, patterns_matching, permission_probes,  # noqa: E402
                           probe_rule, rule)


def load_fixture():
    permissions = []
    for line in io.open(FIXTURE, encoding='utf-8'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        group, target, verb = line.split('|')
        permissions.append((None if group == '-' else group, target, verb))
    return permissions


def test_no_detection_lost(report):
    """Every permission the baseline records must still be detected."""
    lost = []
    for group, target, verb in load_fixture():
        if not patterns_matching(STATIC_RISKY_ROLES, [probe_rule(group, target, verb)]):
            lost.append((group, target, verb))
    report('no detection lost', not lost,
           'lost {0}: {1}'.format(len(lost), lost[:8]))


def test_every_pattern_is_reachable(report):
    """A pattern must fire on a role built from its own rules."""
    unreachable = []
    for pattern in STATIC_RISKY_ROLES:
        kind = CLUSTER_ROLE_KIND if pattern.resource_scope == CLUSTER_SCOPE else ROLE_KIND
        # Drop a bare "*" when named verbs sit beside it: a role holding both is
        # simply a wildcard role, and would be reported as one.
        rules = []
        for pattern_rule in pattern.rules:
            verbs = list(pattern_rule.verbs or [])
            named = [v for v in verbs if v != '*']
            copy = rule(pattern_rule.api_groups, pattern_rule.resources, named or verbs)
            copy.non_resource_ur_ls = pattern_rule.non_resource_ur_ls
            rules.append(copy)
        fired = set(f.pattern_name for f in evaluate_role(RawRole('probe', rules), kind))
        # The two wildcard patterns legitimately subsume anything built from a
        # fully unrestricted rule, so accept either of them standing in.
        if pattern.name not in fired and not (fired & {'risky-wildcard-all',
                                                       'risky-wildcard-resources'}):
            unreachable.append(pattern.name)
    report('every pattern is reachable', not unreachable, str(unreachable))


NEGATIVE_CASES = [
    ('write-only secrets does not trigger the read pattern',
     [rule([''], ['secrets'], ['create'])], ROLE_KIND,
     {'risky-secrets-write'}, {'risky-secrets-read', 'risky-secrets-destroy'}),
    ('read-only secrets does not trigger write or destroy',
     [rule([''], ['secrets'], ['get', 'list'])], ROLE_KIND,
     {'risky-secrets-read'}, {'risky-secrets-write', 'risky-secrets-destroy'}),
    ('a vendor CRD named "secrets" is not the core Secret',
     [rule(['vault.example.com'], ['secrets'], ['get', 'list'])], ROLE_KIND,
     set(), {'risky-secrets-read'}),
    ('read-only pods does not trigger create, update or destroy',
     [rule([''], ['pods'], ['get', 'list', 'watch'])], ROLE_KIND,
     set(), {'risky-pods-create', 'risky-pods-update', 'risky-pods-destroy'}),
    ('read-only deployments does not trigger the write pattern',
     [rule(['apps'], ['deployments'], ['get', 'list'])], ROLE_KIND,
     set(), {'risky-deployments'}),
    ('a cluster-scoped resource in a namespaced Role is not reported',
     [rule([''], ['nodes/proxy'], ['get'])], ROLE_KIND,
     set(), {'risky-nodes-proxy'}),
    ('the same rule in a ClusterRole is reported',
     [rule([''], ['nodes/proxy'], ['get'])], CLUSTER_ROLE_KIND,
     {'risky-nodes-proxy'}, set()),
    ('a two-rule chain does not fire on half of it',
     [rule([''], ['pods'], ['create'])], ROLE_KIND,
     {'risky-pods-create'}, {'risky-chain-pod-and-secrets'}),
    ('a two-rule chain fires when both halves are present',
     [rule([''], ['pods'], ['create']), rule([''], ['secrets'], ['get'])], ROLE_KIND,
     {'risky-chain-pod-and-secrets'}, set()),
    ('wildcard inside one API group is not full cluster wildcard',
     [rule(['constraints.gatekeeper.sh'], ['*'], ['create', 'update'])], CLUSTER_ROLE_KIND,
     {'risky-opa-constraints', 'risky-single-group-wildcard'},
     {'risky-wildcard-all', 'risky-wildcard-resources'}),
    ('total control of an unknown API group is still detected',
     [rule(['vendor.example.com'], ['*'], ['*'])], CLUSTER_ROLE_KIND,
     {'risky-single-group-wildcard'}, set()),
    ('a role with no rules yields nothing', [], ROLE_KIND, set(), None),
    ('an empty verb list yields nothing',
     [rule([''], ['secrets'], [])], ROLE_KIND, set(), None),
]


def test_negative_matching(report):
    for label, rules, kind, expected, forbidden in NEGATIVE_CASES:
        fired = set(f.pattern_name for f in evaluate_role(RawRole('probe', rules), kind))
        ok = expected <= fired
        if forbidden is None:
            ok = ok and not fired
        else:
            ok = ok and not (forbidden & fired)
        report(label, ok, 'fired: {0}'.format(sorted(fired)))


def test_baseline_is_current(report):
    """The fixture must not drift behind the matrix without someone noticing."""
    current = set(permission_probes(STATIC_RISKY_ROLES))
    recorded = set(load_fixture())
    report('baseline covers every permission the matrix names',
           current <= recorded,
           'missing from fixture: {0}'.format(sorted(current - recorded)[:8]))


TESTS = [test_no_detection_lost, test_every_pattern_is_reachable,
         test_negative_matching, test_baseline_is_current]
