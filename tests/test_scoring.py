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
from engine.scan_context import (BoundBinding, ScanContext,  # noqa: E402
                                 is_sensitive_namespace, load_sensitive_namespaces)
from engine.scoring import (MODIFIER_ORDER, score_finding,  # noqa: E402
                            score_findings_for_scope)
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
        ('resourceNames still narrows when a collection verb sits beside get',
         ('risky-secrets-read', ROLE_PLAIN, context({ROLE_PLAIN_KEY: [RB_PLAIN]}),
          [rule([''], ['secrets'], ['get', 'list'], resource_names=['one'])]),
         Priority.MEDIUM, ['resourceNamesRestricted']),
        ('resourceNames narrows a subresource create',
         ('risky-serviceaccount-token', ROLE_PLAIN, context({ROLE_PLAIN_KEY: [RB_PLAIN]}),
          [rule([''], ['serviceaccounts/token'], ['create'], resource_names=['one'])]),
         Priority.HIGH, ['resourceNamesRestricted']),
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


PINNED_GET = rule([''], ['secrets'], ['get', 'update'], resource_names=['one'])
OPEN_CREATE = rule([''], ['secrets'], ['create'])


def test_resource_names_follow_rbac(report):
    """A pinned rule is worth what RBAC actually grants through it.

    RBAC reads the object name from the request path. That makes 'resourceNames'
    a real restriction on some verbs, a grant of nothing on others, and the
    difference decides both whether a pattern fires and what it scores.
    """
    def matches(pattern_name, rules):
        pattern = next(p for p in STATIC_RISKY_ROLES if p.name == pattern_name)
        return are_rules_contain_other_rules(rules, pattern.rules)

    # A create of a top-level resource never names an object, so the rule
    # authorizes no create at all and there is nothing to report.
    report('a pinned top-level create grants nothing and does not fire',
           not matches('risky-secrets-write',
                       [rule([''], ['secrets'], ['create'], resource_names=['one'])]),
           'pattern still fired')

    # A subresource create names its parent, which is how token minting is
    # scoped, so the pattern must fire and keep the discount.
    report('a pinned subresource create still fires',
           bool(matches('risky-serviceaccount-token',
                        [rule([''], ['serviceaccounts/token'], ['create'],
                              resource_names=['one'])])),
           'pattern did not fire')

    # The leader-election shape: one rule pinned by name, one not. The pin is
    # not a restriction on the role, only on one of its two rules.
    both_orders = []
    for label, rules in (('pinned first', [PINNED_GET, OPEN_CREATE]),
                         ('unpinned first', [OPEN_CREATE, PINNED_GET])):
        priority, modifiers = score('risky-secrets-write', ROLE_PLAIN,
                                    context({ROLE_PLAIN_KEY: [RB_PLAIN]}), rules)
        both_orders.append((priority, modifiers))
        report('an unrestricted rule beside a pinned one loses the discount, '
               + label,
               modifiers == [],
               'got {0} {1}'.format(priority.name, modifiers))

    report('rule order does not change the verdict',
           both_orders[0] == both_orders[1],
           'got {0} then {1}'.format(*both_orders))

    # Both rules grant part of what the pattern asks for, and the report should
    # say so rather than name whichever rule was written first.
    matched = matches('risky-secrets-write', [PINNED_GET, OPEN_CREATE])
    verbs = matched[0].matched_verbs if matched else []
    report('the match reports every verb the role grants',
           verbs == ['create', 'update'],
           'got {0}'.format(verbs))


def test_sensitive_namespaces_match_by_name_and_prefix(report):
    """A distribution's platform namespaces share a stem; app namespaces must not.

    The dangerous direction here is over-matching: a prefix that also swallows
    team namespaces raises half the cluster by one level and the modifier stops
    meaning anything.
    """
    patterns = set(['kube-system', 'infra', 'shturval-*'])
    cases = [
        ('an exact name still matches', 'kube-system', True),
        ('an unlisted namespace does not', 'team-a', False),
        ('a prefix entry covers what grows under it', 'shturval-monitoring', True),
        ('a prefix entry needs its separator', 'shturvalx', False),
        ('a prefix entry does not match the stem alone', 'shturval', False),
        ('an exact entry never becomes a prefix', 'infra-sandbox', False),
    ]
    for label, namespace, expected in cases:
        report(label, is_sensitive_namespace(namespace, patterns) == expected,
               '{0} -> {1}'.format(namespace, is_sensitive_namespace(namespace, patterns)))

    shipped = load_sensitive_namespaces()
    report('the shipped list still covers the Kubernetes control plane',
           all(is_sensitive_namespace(ns, shipped)
               for ns in ('kube-system', 'kube-public', 'kube-node-lease')),
           str(sorted(shipped)[:5]))


def test_binding_scope_is_explained_and_isolated(report):
    """A binding reports its own verdict, its own reason, and nothing else's.

    The binding report is the only place that says which binding made a role
    critical, so an empty explanation there sends a reader back to the cluster.
    And because a ClusterRole reached by both a ClusterRoleBinding and a
    RoleBinding is two grants of different severity, scoring one binding must
    leave the role-level finding - the worst case - untouched.
    """
    rules = [rule(['rbac.authorization.k8s.io'], ['clusterrolebindings'], ['create'])]
    ctx = context({CR_KEY: [CRB, RB_PLAIN]})
    pattern = next(p for p in STATIC_RISKY_ROLES
                   if p.name == 'risky-clusterrolebindings-write')
    finding = Finding(pattern, are_rules_contain_other_rules(rules, pattern.rules))
    score_finding(finding, CR, ctx, second_pass=True)

    scoped = score_findings_for_scope([finding], CR, ctx.scoped_to(RB_PLAIN),
                                      second_pass=True)
    rendered = scoped[0].render()

    report('a binding is scored in its own scope, not the role\'s',
           scoped[0].priority == Priority.HIGH
           and [m.name for m in scoped[0].modifiers] == ['namespacedBindingOnly'],
           'got {0} {1}'.format(scoped[0].priority.name,
                                [m.name for m in scoped[0].modifiers]))
    report('a binding explains its verdict in one line',
           rendered.count('\n') == 0
           and pattern.name in rendered
           and 'CRITICAL -> HIGH' in rendered
           and rendered.endswith('(namespacedBindingOnly)'),
           'rendered as: ' + rendered.replace('\n', ' | '))
    report('--explain brings back the matched rules',
           'clusterrolebindings: create' in scoped[0].render_verbose(),
           'rendered as: ' + scoped[0].render_verbose().replace('\n', ' | '))
    report('scoring a binding leaves the role-level finding alone',
           finding.priority == Priority.CRITICAL
           and [m.name for m in finding.modifiers] == ['clusterWide'],
           'role-level became {0} {1}'.format(finding.priority.name,
                                              [m.name for m in finding.modifiers]))


def test_report_vocabulary_is_ascii(report):
    """Every string a report can emit stays ASCII.

    The findings are shipped to Splunk by a log collector, and a stray non-ASCII
    character in a pattern name, a category or a modifier explanation is the
    kind of thing that breaks a parser long after the scan looked fine.
    """
    strings = []
    for pattern in STATIC_RISKY_ROLES:
        strings += [pattern.name, pattern.category or '', pattern.summary or '',
                    pattern.description or '', pattern.impact or '']
    strings += MODIFIER_ORDER
    strings += [p.name for p in Priority]

    ctx = context({CR_KEY: [CRB_EVERYONE]})
    pattern = next(p for p in STATIC_RISKY_ROLES if p.name == 'risky-secrets-read')
    finding = Finding(pattern, are_rules_contain_other_rules(SECRETS_READ, pattern.rules))
    score_finding(finding, CR, ctx, second_pass=True)
    strings.append(finding.render())

    offenders = [s for s in strings if any(ord(c) > 127 for c in s)]
    report('every string a report can emit is ASCII',
           not offenders, 'non-ASCII in: ' + ', '.join(offenders[:5]))


def test_first_pass_defers_service_account_modifier(report):
    """Pass one must not use the map pass two builds from its own result."""
    ctx = context({ROLE_PLAIN_KEY: [RB_PLAIN]}, {'plain-ns': set(['sa', 'other'])})
    priority, modifiers = score('risky-pods-create', ROLE_PLAIN, ctx, PODS_CREATE,
                                second_pass=False)
    report('the first pass never applies privilegedSaReachable',
           priority == Priority.HIGH and not modifiers,
           'got {0} {1}'.format(priority.name, modifiers))


TESTS = [test_modifiers,
         test_resource_names_follow_rbac,
         test_sensitive_namespaces_match_by_name_and_prefix,
         test_binding_scope_is_explained_and_isolated,
         test_report_vocabulary_is_ascii,
         test_first_pass_defers_service_account_modifier]
