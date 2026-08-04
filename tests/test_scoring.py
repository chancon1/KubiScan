"""Each context modifier must move a score exactly under its own condition.

The bugs these caught while the model was being written were all of one shape:
a modifier that fires slightly too often. That is the dangerous direction here -
it inflates severities until the top of the report means nothing again, which is
the problem the whole rework exists to fix.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.finding import Finding  # noqa: E402
from engine.priority import Priority  # noqa: E402
from engine.scan_context import BoundBinding, ScanContext  # noqa: E402
from engine.scoring import score_finding  # noqa: E402
from engine.utils import are_rules_contain_other_rules  # noqa: E402
from misc.constants import (CLUSTER_ROLE_BINDING_KIND, CLUSTER_ROLE_KIND,  # noqa: E402
                            ROLE_BINDING_KIND, ROLE_KIND)
from static_risky_roles import STATIC_RISKY_ROLES  # noqa: E402
from tests.helpers import Subject, rule  # noqa: E402

SENSITIVE = set(['kube-system'])


class Target(object):
    """The scored Role/ClusterRole, as scoring sees it."""

    def __init__(self, kind, name, namespace=None):
        self.kind = kind
        self.name = name
        self.namespace = namespace


def context(index, privileged=None):
    ctx = ScanContext([], [], sensitive_namespaces=SENSITIVE)
    ctx._index = dict(index)
    if privileged is not None:
        ctx.privileged_service_accounts = privileged
        ctx.privileged_sa_known = True
    return ctx


def score(pattern_name, target, ctx, rules, second_pass=True):
    pattern = next(p for p in STATIC_RISKY_ROLES if p.name == pattern_name)
    matches = are_rules_contain_other_rules(rules, pattern.rules)
    assert matches, 'probe does not match ' + pattern_name
    finding = Finding(pattern, matches)
    score_finding(finding, target, ctx, second_pass=second_pass)
    return finding.priority, sorted(m.name for m in finding.modifiers)


SECRETS_READ = [rule([''], ['secrets'], ['get', 'list'])]
PODS_CREATE = [rule([''], ['pods'], ['create'])]

CRB = BoundBinding(CLUSTER_ROLE_BINDING_KIND, 'crb', None,
                   [Subject('ServiceAccount', 'sa', 'ns')])
CRB_EVERYONE = BoundBinding(CLUSTER_ROLE_BINDING_KIND, 'crb-all', None,
                            [Subject('Group', 'system:authenticated')])
RB_PLAIN = BoundBinding(ROLE_BINDING_KIND, 'rb', 'plain-ns',
                        [Subject('ServiceAccount', 'sa', 'plain-ns')])
RB_SENSITIVE = BoundBinding(ROLE_BINDING_KIND, 'rb', 'kube-system',
                            [Subject('ServiceAccount', 'sa', 'kube-system')])

CR = Target(CLUSTER_ROLE_KIND, 'cr')
ROLE_PLAIN = Target(ROLE_KIND, 'r', 'plain-ns')
ROLE_SENSITIVE = Target(ROLE_KIND, 'r', 'kube-system')

CR_KEY = (CLUSTER_ROLE_KIND, 'cr', None)
ROLE_PLAIN_KEY = (ROLE_KIND, 'r', 'plain-ns')
ROLE_SENSITIVE_KEY = (ROLE_KIND, 'r', 'kube-system')


def test_modifiers(report):
    cases = [
        ('unbound lowers HIGH to MEDIUM',
         ('risky-secrets-read', CR, context({}), SECRETS_READ),
         Priority.MEDIUM, ['unbound']),
        ('clusterWide raises HIGH to CRITICAL',
         ('risky-secrets-read', CR, context({CR_KEY: [CRB]}), SECRETS_READ),
         Priority.CRITICAL, ['clusterWide']),
        ('a bound Role in an ordinary namespace stays at base',
         ('risky-secrets-read', ROLE_PLAIN, context({ROLE_PLAIN_KEY: [RB_PLAIN]}), SECRETS_READ),
         Priority.HIGH, []),
        ('sensitiveNamespace raises HIGH to CRITICAL',
         ('risky-secrets-read', ROLE_SENSITIVE,
          context({ROLE_SENSITIVE_KEY: [RB_SENSITIVE]}), SECRETS_READ),
         Priority.CRITICAL, ['sensitiveNamespace']),
        ('sensitiveNamespace does not double-charge a cluster-wide grant',
         ('risky-secrets-read', CR, context({CR_KEY: [CRB]}), SECRETS_READ),
         Priority.CRITICAL, ['clusterWide']),
        ('boundToEveryone fires on system:authenticated',
         ('risky-secrets-read', CR, context({CR_KEY: [CRB_EVERYONE]}), SECRETS_READ),
         Priority.CRITICAL, ['boundToEveryone', 'clusterWide']),
        ('namespacedBindingOnly lowers an inert cluster-scoped grant',
         ('risky-clusterrolebindings-write', CR, context({CR_KEY: [RB_PLAIN]}),
          [rule(['rbac.authorization.k8s.io'], ['clusterrolebindings'], ['create'])]),
         Priority.HIGH, ['namespacedBindingOnly']),
        ('resourceNames lowers a name-pinned get',
         ('risky-secrets-read', ROLE_PLAIN, context({ROLE_PLAIN_KEY: [RB_PLAIN]}),
          [rule([''], ['secrets'], ['get'], resource_names=['one'])]),
         Priority.MEDIUM, ['resourceNamesRestricted']),
        ('resourceNames earns nothing once list is among the matched verbs',
         ('risky-secrets-read', ROLE_PLAIN, context({ROLE_PLAIN_KEY: [RB_PLAIN]}),
          [rule([''], ['secrets'], ['get', 'list'], resource_names=['one'])]),
         Priority.HIGH, []),
        ('resourceNames earns nothing on create',
         ('risky-secrets-write', ROLE_PLAIN, context({ROLE_PLAIN_KEY: [RB_PLAIN]}),
          [rule([''], ['secrets'], ['create'], resource_names=['one'])]),
         Priority.HIGH, []),
        ('resourceNames applies to use, cancelling clusterWide',
         ('risky-podsecuritypolicies-use', CR, context({CR_KEY: [CRB]}),
          [rule(['policy'], ['podsecuritypolicies'], ['use'], resource_names=['p'])]),
         Priority.HIGH, ['clusterWide', 'resourceNamesRestricted']),
        ("privilegedSaReachable ignores the role's own service account",
         ('risky-pods-create', ROLE_PLAIN,
          context({ROLE_PLAIN_KEY: [RB_PLAIN]}, {'plain-ns': set(['sa'])}), PODS_CREATE),
         Priority.HIGH, []),
        ('privilegedSaReachable fires on a different critical account',
         ('risky-pods-create', ROLE_PLAIN,
          context({ROLE_PLAIN_KEY: [RB_PLAIN]}, {'plain-ns': set(['sa', 'other'])}), PODS_CREATE),
         Priority.CRITICAL, ['privilegedSaReachable']),
        ('a finding never decays below LOW',
         ('risky-secrets-destroy', CR, context({}), [rule([''], ['secrets'], ['delete'])]),
         Priority.LOW, ['unbound']),
    ]
    for label, args, expected_priority, expected_modifiers in cases:
        priority, modifiers = score(*args)
        report(label,
               priority == expected_priority and modifiers == expected_modifiers,
               'got {0} {1}'.format(priority.name, modifiers))


def test_first_pass_defers_service_account_modifier(report):
    """Pass one must not use the map pass two builds from its own result."""
    ctx = context({ROLE_PLAIN_KEY: [RB_PLAIN]}, {'plain-ns': set(['sa', 'other'])})
    priority, modifiers = score('risky-pods-create', ROLE_PLAIN, ctx, PODS_CREATE,
                                second_pass=False)
    report('the first pass never applies privilegedSaReachable',
           priority == Priority.HIGH and not modifiers,
           'got {0} {1}'.format(priority.name, modifiers))


TESTS = [test_modifiers, test_first_pass_defers_service_account_modifier]
