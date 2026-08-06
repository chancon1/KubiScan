"""Escalation chains a subject completes by holding several roles at once.

``evaluate_role`` looks at one Role or ClusterRole at a time, so a chain pattern
- "create pods" AND "get secrets" - only fires where a single role happens to
grant both legs. Real clusters rarely look like that. Privileges arrive through
several bindings, and a service account holding two unremarkable roles can do
exactly what the one dangerous role could.

This module closes that gap. It gathers what each subject may do, splits that by
where the grants actually apply, and runs the chain patterns over the result.

Two things decide whether a chain is real, and both are easy to get wrong:

* **Where.** Creating a pod in one namespace does not reach secrets in another,
  so legs are only combined when they land in the same place. A ClusterRoleBinding
  applies everywhere and therefore joins every namespace; a RoleBinding joins
  only its own.
* **Who.** A binding hands its role to each of its subjects separately. Two
  subjects on one binding do not pool their permissions, so each is followed on
  its own.
"""

from engine.finding import Finding
from engine.scan_context import BoundBinding
from engine.scoring import score_findings_for_scope
from engine.utils import are_rules_contain_other_rules
from misc.constants import CLUSTER_ROLE_KIND, ROLE_KIND, SERVICEACCOUNT_KIND
from static_risky_roles import STATIC_RISKY_ROLES

# Only multi-rule patterns can be split across roles. A single-rule pattern is
# satisfied by one rule of one role, which evaluate_role() already sees.
CHAIN_PATTERNS = [pattern for pattern in STATIC_RISKY_ROLES if len(pattern.rules) > 1]


class _Grant(object):
    """One role a subject holds, and the binding that handed it over."""

    def __init__(self, role_key, binding, rules):
        self.role_key = role_key
        self.binding = binding
        self.rules = rules

    @property
    def role_name(self):
        return self.role_key[1]

    @property
    def is_system_role(self):
        return self.role_name.startswith('system:')

    @property
    def role_display(self):
        kind, name, namespace = self.role_key
        if kind == ROLE_KIND:
            return 'Role {0}/{1}'.format(namespace, name)
        return 'ClusterRole {0}'.format(name)

    @property
    def binding_display(self):
        if self.binding.is_cluster_wide:
            return 'ClusterRoleBinding {0}'.format(self.binding.name)
        return 'RoleBinding {0}/{1}'.format(self.binding.namespace, self.binding.name)


class ChainScope(object):
    """Stands in for a Role while a subject's chain is scored.

    Scoring asks a role three things - its kind, its name and its namespace -
    and the answers decide which modifiers may fire. A chain confined to one
    namespace answers like a Role even when a ClusterRole supplied one of its
    legs, because that is the reach the chain actually has.
    """

    def __init__(self, kind, name, namespace=None):
        self.kind = kind
        self.name = name
        self.namespace = namespace


class SubjectChain(object):
    """One escalation chain a subject completes across several roles."""

    def __init__(self, subject, identity, scope, finding, legs):
        self.subject = subject
        self.identity = identity
        self.scope = scope
        self.finding = finding
        # [(RuleMatch, [_Grant])] in pattern order: which role supplied which leg.
        self.legs = legs

    @property
    def grants(self):
        seen = []
        for _, grants in self.legs:
            for grant in grants:
                if grant not in seen:
                    seen.append(grant)
        return seen

    @property
    def is_cluster_wide(self):
        return self.scope.kind == CLUSTER_ROLE_KIND


def _subject_identity(subject, binding):
    """A hashable identity for a subject, with the namespace RBAC would use.

    A ServiceAccount subject may leave its namespace out of a RoleBinding, in
    which case the binding's own namespace applies. Resolving that here rather
    than writing it back onto the subject keeps the API objects untouched -
    several reports share them.
    """
    kind = getattr(subject, 'kind', None) or 'Subject'
    name = getattr(subject, 'name', None) or ''
    namespace = None
    if kind == SERVICEACCOUNT_KIND:
        namespace = getattr(subject, 'namespace', None) or binding.namespace
    return (kind, name, namespace)


def _grants_by_subject(ctx):
    """identity -> [_Grant], for every subject the cluster binds to anything."""
    by_subject = {}
    for role_key, binding in ctx.iter_bindings():
        rules = ctx.rules_for_key(role_key)
        if not rules:
            continue
        for subject in binding.subjects or []:
            identity = _subject_identity(subject, binding)
            entry = by_subject.setdefault(identity, (subject, []))
            entry[1].append(_Grant(role_key, binding, rules))
    return by_subject


def _legs_of(matches, provenance):
    """Which grants supplied each leg of a matched chain.

    Reported per leg rather than as one list of roles: "pod creation comes from
    here, secret reading from there" is the sentence that makes a cross-role
    chain actionable, and a flat list of two roles does not say it.
    """
    legs = []
    for match in matches:
        suppliers = []
        for source_rule in match.source_rules:
            for rule, grant in provenance:
                if rule is source_rule and grant not in suppliers:
                    suppliers.append(grant)
        legs.append((match, suppliers))
    return legs


def _cross_role_chains(grants, kind):
    """Chain patterns these grants satisfy together but none satisfies alone."""
    if len(grants) < 2:
        return []
    rules = []
    provenance = []
    for grant in grants:
        for rule in grant.rules:
            rules.append(rule)
            provenance.append((rule, grant))

    found = []
    for pattern in CHAIN_PATTERNS:
        if not pattern.applies_to_kind(kind):
            continue
        matches = are_rules_contain_other_rules(rules, pattern.rules)
        if not matches:
            continue
        # A role granting the whole chain by itself is already reported against
        # that role, and repeating it here would be the same finding twice.
        if any(are_rules_contain_other_rules(grant.rules, pattern.rules)
               for grant in grants):
            continue
        found.append((Finding(pattern, matches), _legs_of(matches, provenance)))
    return found


def _narrowed(binding, identity):
    """A copy of the binding carrying only the subject being followed.

    Scoring reads the subject list to decide whether the grant went to everyone
    and which service accounts are within reach. Handing it the whole list would
    answer those questions about the binding's other subjects, who hold their
    own permissions and not this subject's.
    """
    subjects = [subject for subject in (binding.subjects or [])
                if _subject_identity(subject, binding) == identity]
    return BoundBinding(binding.kind, binding.name, binding.namespace, subjects,
                        binding.time)


def _chains_for_subject(subject, identity, grants, ctx):
    cluster = [grant for grant in grants if grant.binding.is_cluster_wide]
    by_namespace = {}
    for grant in grants:
        if grant.binding.is_cluster_wide or grant.binding.namespace is None:
            continue
        by_namespace.setdefault(grant.binding.namespace, []).append(grant)

    chains = []
    everywhere = set()
    name = '{0} {1}'.format(identity[0], identity[1])

    # A chain built only from ClusterRoleBindings holds in every namespace.
    for finding, legs in _cross_role_chains(cluster, CLUSTER_ROLE_KIND):
        everywhere.add(finding.pattern_name)
        chains.append(_scored(subject, identity,
                              ChainScope(CLUSTER_ROLE_KIND, name), finding, legs, ctx))

    for namespace, namespaced in sorted(by_namespace.items()):
        for finding, legs in _cross_role_chains(cluster + namespaced, ROLE_KIND):
            # Already reported as reaching every namespace, this one included.
            if finding.pattern_name in everywhere:
                continue
            chains.append(_scored(subject, identity,
                                  ChainScope(ROLE_KIND, name, namespace), finding,
                                  legs, ctx))
    return chains


def _scored(subject, identity, scope, finding, legs, ctx):
    bindings = []
    for _, suppliers in legs:
        for grant in suppliers:
            narrowed = _narrowed(grant.binding, identity)
            if narrowed not in bindings:
                bindings.append(narrowed)
    scored = score_findings_for_scope([finding], scope, ctx.scoped_to(*bindings),
                                      second_pass=True)[0]
    return SubjectChain(subject, identity, scope, scored, legs)


def build_subject_chains(ctx):
    """Every escalation chain no single role explains, worst first."""
    chains = []
    for identity, (subject, grants) in sorted(
            _grants_by_subject(ctx).items(),
            key=lambda item: tuple(str(part) for part in item[0])):
        chains.extend(_chains_for_subject(subject, identity, grants, ctx))
    return chains
