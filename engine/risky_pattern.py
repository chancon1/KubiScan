from misc.constants import *

# A pattern whose resource lives outside any namespace can only be granted
# through a ClusterRole that a ClusterRoleBinding references. Namespaced Roles
# never grant it, so matching one is a false positive rather than a finding.
CLUSTER_SCOPE = 'cluster'
NAMESPACED_SCOPE = 'namespaced'


class RiskyPattern:
    """One entry of risky_roles.yaml.

    Replaces the Role object the matrix used to be loaded into: a pattern is a
    template, not a role, and it now carries the context rules ('modifiers')
    that turn its declared base priority into an effective one.
    """

    def __init__(self, name, base_priority, rules, resource_scope=NAMESPACED_SCOPE,
                 applies_to=None, modifiers=None, category=None, description=None,
                 summary=None, impact=None, any_api_group=False):
        self.name = name
        self.base_priority = base_priority
        self.rules = rules
        self.resource_scope = resource_scope
        self.applies_to = applies_to or [ROLE_KIND, CLUSTER_ROLE_KIND]
        self.modifiers = modifiers or {}
        self.category = category
        self.description = description
        # Optional report vocabulary. ``summary`` is a short verb phrase such
        # as "read Kubernetes Secrets"; ``impact`` says what the permission
        # makes possible. Patterns without either field still produce a useful
        # event from their matched rules, which lets the matrix migrate without
        # making all 170 entries change at once.
        self.summary = summary
        self.impact = impact
        self.any_api_group = any_api_group

    @property
    def subsumes_all(self):
        """Does this pattern cover every resource of every API group?

        Such a pattern makes all more specific ones redundant, so once it
        matches there is nothing to gain from reporting the rest. The verbs are
        deliberately not part of the test: a role granting named verbs on "*"
        resources still reaches every resource type, and enumerating the ~150
        patterns it technically matches makes the report unreadable while
        saying nothing extra.

        A pattern matching any single group is explicitly not one of these: full
        control of one vendor's API group is a real finding, but it subsumes
        nothing outside that group.
        """
        if self.any_api_group:
            return False
        return all(
            rule.resources == ["*"]
            and (rule.api_groups is None or rule.api_groups == ["*"])
            for rule in self.rules
        )

    def applies_to_kind(self, kind):
        """Whether this pattern can produce a real grant in a role of 'kind'."""
        if kind not in self.applies_to:
            return False
        if self.resource_scope == CLUSTER_SCOPE and kind == ROLE_KIND:
            return False
        return True
