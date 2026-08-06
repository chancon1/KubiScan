from engine.finding import AppliedModifier
from engine.priority import Priority

# Which verbs a 'resourceNames' rule can and cannot grant is decided when the
# rule is matched, by engine.rule.carries_object_name. By the time a finding
# reaches this module the verbs a pinned rule grants nothing for are already
# gone, so scoring only has to ask whether every granting rule was pinned.

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

# Two questions, deliberately kept apart.
#
# Severity asks what the permission lets you do. Only modifiers that change the
# capability itself belong to it: a name-pinned rule reaches fewer objects, an
# inert cluster-scoped rule grants nothing, and a critical service account
# standing next to a pod-creation right is a real escalation step.
#
# Priority asks how urgently a human should look, and adds where the grant lands
# and who holds it. Those never change what the permission can do - the same
# rule cluster-wide and in one team namespace is the same capability - but they
# decide what gets reviewed first.
CAPABILITY_MODIFIERS = frozenset([
    'namespacedBindingOnly',
    'privilegedSaReachable',
    'resourceNamesRestricted',
])

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
        names = [b.name for b in ctx.granting_bindings(role) if b.is_cluster_wide]
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
    """Every rule granting this permission is pinned to named objects.

    All of them, not one of them: a single unrestricted rule loses the discount
    even when another rule of the same role is pinned, because the permission is
    still reachable without naming an object.

    Verbs a pinned rule cannot grant at all were already dropped when the rule
    was matched, so whatever reaches this point really is narrowed by name.
    """
    if not finding.rule_matches:
        return False, None, None
    names = []
    for match in finding.rule_matches:
        for source_rule in match.source_rules:
            restricted = getattr(source_rule, 'resource_names', None)
            if not restricted:
                return False, None, None
            names.extend(restricted)
    shown = ', '.join(sorted(set(names)))
    return True, 'restricted to resourceNames: ' + shown, shown


def _unbound(finding, role, ctx):
    """Nobody holds this permission - the definition exists, the grant does not.

    A binding whose subject list is empty lands here too, and saying that no
    binding references the role would be false: one does, it just hands the role
    to nobody. The distinction is what a reader needs to fix it.
    """
    if ctx.is_bound(role):
        return False, None, None
    bindings = ctx.bindings_for(role)
    if not bindings:
        return True, 'no RoleBinding or ClusterRoleBinding references this role', None
    if len(bindings) == 1:
        return True, 'the binding has no subjects, so nobody currently receives the grant', None
    return True, 'no binding of this role has any subjects, so nobody receives the grant', None


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
    """Return (capability_delta, exposure_delta, applied) without touching it."""
    capability = 0
    exposure = 0
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
            if name in CAPABILITY_MODIFIERS:
                capability += configured
            else:
                exposure += configured
            applied.append(AppliedModifier(name, configured, explanation, detail))
    return capability, exposure, applied


def _verdict(base, capability, exposure):
    """(severity, priority) from a base score and the two kinds of delta.

    Priority is clamped once from the full sum rather than stacked on top of an
    already-clamped severity. Clamping twice would quietly change scores that
    have nothing to do with the split - a CRITICAL pattern pushed up by
    capability and back down by exposure would come out a level lower than the
    arithmetic says.
    """
    return adjust(base, capability), adjust(base, capability + exposure)


def score_findings_for_scope(findings, role, ctx, second_pass=False):
    """Score findings in a narrower context, returning copies.

    Used for one binding, where the report needs the same arithmetic the role
    level shows - which modifier fired and why - while the role-level findings
    keep the worst case across every binding.
    """
    scored = []
    for finding in findings:
        capability, exposure, applied = evaluate_modifiers(finding, role, ctx, second_pass)
        severity, priority = _verdict(finding.base_priority, capability, exposure)
        scored.append(finding.rescored(severity, priority, applied))
    return scored


def score_finding(finding, role, ctx, second_pass=False):
    """Recompute a finding's severity and priority from its base and context.

    Safe to call twice: the modifier list is rebuilt from scratch each time, so
    the second pass (which alone knows about privileged service accounts) does
    not double-count what the first already applied.
    """
    capability, exposure, applied = evaluate_modifiers(finding, role, ctx, second_pass)
    finding.modifiers = applied
    finding.severity, finding.priority = _verdict(finding.base_priority, capability, exposure)
    return finding.priority


def highest_priority(findings):
    return _highest(findings, 'priority')


def highest_severity(findings):
    return _highest(findings, 'severity')


def _highest(findings, attribute):
    """The strongest single finding, never a sum.

    Holding twenty risky permissions is not worse than holding the worst of
    them: a count would let a noisy operator role outrank a quiet one that can
    read every secret in the cluster.
    """
    highest = Priority.NONE
    for finding in findings:
        value = getattr(finding, attribute)
        if value.value > highest.value:
            highest = value
    return highest
