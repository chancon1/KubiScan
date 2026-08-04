from engine.finding import AppliedModifier
from engine.priority import Priority

# Verbs that a 'resourceNames' restriction does NOT narrow. RBAC cannot restrict
# 'create' by name (the object has none yet at authorization time), and a
# collection request carries no name to match either. A wildcard verb includes
# both, so it is listed here too.
#
# Everything else is narrowed, and stating it as a deny-list matters: the
# name-restricted verbs that are easy to forget are exactly the dangerous ones -
# 'use' on a PodSecurityPolicy, 'bind' and 'escalate' on a named role,
# 'impersonate' on a named account, 'approve'/'sign' on a named signer. All of
# those exist precisely to be pinned to specific objects.
RESOURCE_NAME_IGNORING_VERBS = frozenset(
    ['create', 'list', 'watch', 'deletecollection', '*'])

# Applied in this order, which is also the order they are shown in a report.
MODIFIER_ORDER = [
    'clusterWide',
    'namespacedBindingOnly',
    'sensitiveNamespace',
    'boundToEveryone',
    'privilegedSaReachable',
    'resourceNamesRestricted',
    'unbound',
]

# Everything the second pass needs; the first pass skips these so that the
# service-account map it feeds can be built without depending on itself.
SECOND_PASS_MODIFIERS = frozenset(['privilegedSaReachable'])

_PRIORITY_BY_VALUE = {p.value: p for p in Priority}


def adjust(priority, delta):
    """Move a priority by 'delta' levels, clamped to LOW..CRITICAL.

    A match never decays into NONE: context can make a finding less urgent, but
    the permission is still there and still belongs in the report.
    """
    value = priority.value + delta
    value = max(Priority.LOW.value, min(Priority.CRITICAL.value, value))
    return _PRIORITY_BY_VALUE[value]


def _cluster_wide(finding, role, ctx):
    """The binding names are detail only for --explain: the one-line form says
    'clusterWide', and the same event already lists every binding by name."""
    if ctx.is_cluster_wide(role):
        names = [b.name for b in ctx.bindings_for(role) if b.is_cluster_wide]
        return True, 'cluster-wide via ClusterRoleBinding: ' + ', '.join(sorted(names)), None
    return False, None, None


def _namespaced_binding_only(finding, role, ctx):
    if ctx.is_namespaced_binding_only(role):
        return True, 'ClusterRole bound only by RoleBindings, cluster-scoped rules inert', None
    return False, None, None


def _sensitive_namespace(finding, role, ctx):
    # A cluster-wide grant already covers every sensitive namespace there is,
    # and 'clusterWide' has accounted for it. Counting both would double-charge
    # the same fact.
    if ctx.is_cluster_wide(role):
        return False, None, None
    hit = ctx.sensitive_namespaces_hit(role)
    if hit:
        return True, 'sensitive namespace: ' + ', '.join(hit), ', '.join(hit)
    return False, None, None


def _bound_to_everyone(finding, role, ctx):
    """Handed to every user of the cluster, authenticated or not."""
    groups = ctx.bound_to_everyone(role)
    if groups:
        return True, 'granted to ' + ', '.join(groups), ', '.join(groups)
    return False, None, None


def _privileged_sa_reachable(finding, role, ctx):
    matched, accounts = ctx.reaches_privileged_sa(role)
    if not matched:
        return False, None, None
    return True, 'critical service account reachable: ' + accounts, accounts


def _resource_names_restricted(finding, role, ctx):
    """Every matched rule is pinned to named objects, on verbs that respect it."""
    if not finding.rule_matches:
        return False, None, None
    names = []
    for match in finding.rule_matches:
        restricted = getattr(match.source_rule, 'resource_names', None)
        if not restricted:
            return False, None, None
        if set(v.lower() for v in match.matched_verbs) & RESOURCE_NAME_IGNORING_VERBS:
            return False, None, None
        names.extend(restricted)
    shown = ', '.join(sorted(set(names)))
    return True, 'restricted to resourceNames: ' + shown, shown


def _unbound(finding, role, ctx):
    if not ctx.is_bound(role):
        return True, 'no RoleBinding or ClusterRoleBinding references this role', None
    return False, None, None


MODIFIER_EVALUATORS = {
    'clusterWide': _cluster_wide,
    'namespacedBindingOnly': _namespaced_binding_only,
    'sensitiveNamespace': _sensitive_namespace,
    'boundToEveryone': _bound_to_everyone,
    'privilegedSaReachable': _privileged_sa_reachable,
    'resourceNamesRestricted': _resource_names_restricted,
    'unbound': _unbound,
}


def evaluate_modifiers(finding, role, ctx, second_pass=False):
    """Return (delta, applied_modifiers) without touching the finding."""
    delta = 0
    applied = []
    for name in MODIFIER_ORDER:
        configured = finding.pattern.modifiers.get(name)
        if not configured:
            continue
        if name in SECOND_PASS_MODIFIERS and not second_pass:
            continue
        evaluator = MODIFIER_EVALUATORS.get(name)
        if evaluator is None:
            continue
        matched, explanation, detail = evaluator(finding, role, ctx)
        if matched:
            delta += configured
            applied.append(AppliedModifier(name, configured, explanation, detail))
    return delta, applied


def score_findings_for_scope(findings, role, ctx, second_pass=False):
    """Score findings in a narrower context, returning copies.

    Used for one binding, where the report needs the same arithmetic the role
    level shows - which modifier fired and why - while the role-level findings
    keep the worst case across every binding.
    """
    scored = []
    for finding in findings:
        delta, applied = evaluate_modifiers(finding, role, ctx, second_pass)
        scored.append(finding.rescored(adjust(finding.base_priority, delta), applied))
    return scored


def score_finding(finding, role, ctx, second_pass=False):
    """Recompute a finding's effective priority from its base and the context.

    Safe to call twice: the modifier list is rebuilt from scratch each time, so
    the second pass (which alone knows about privileged service accounts) does
    not double-count what the first already applied.
    """
    delta, applied = evaluate_modifiers(finding, role, ctx, second_pass)
    finding.modifiers = applied
    finding.priority = adjust(finding.base_priority, delta)
    return finding.priority


def highest_priority(findings):
    highest = Priority.NONE
    for finding in findings:
        if finding.priority.value > highest.value:
            highest = finding.priority
    return highest
