import os

from engine.rule import Rule
from engine.utils import are_rules_contain_other_rules
from misc.constants import CLUSTER_ROLE_KIND, ROLE_KIND

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, 'fixtures', 'detected_permissions.txt')


class Meta(object):
    def __init__(self, name, namespace=None):
        self.name = name
        self.namespace = namespace
        self.creation_timestamp = None


class RawRole(object):
    """Stands in for the V1Role/V1ClusterRole the API client would return."""

    def __init__(self, name, rules, namespace=None):
        self.metadata = Meta(name, namespace)
        self.rules = rules


class Subject(object):
    def __init__(self, kind, name, namespace=None):
        self.kind = kind
        self.name = name
        self.namespace = namespace


def rule(groups, resources, verbs, resource_names=None):
    return Rule(resources=resources, verbs=verbs, api_groups=groups,
                resource_names=resource_names)


def permission_probes(patterns):
    """Every (apiGroup, resource, verb) detectable from that permission alone.

    A None apiGroup marks a nonResourceURL, whose 'resource' is the URL itself.

    Multi-rule patterns are skipped on purpose: they are escalation chains, and
    every rule of a pattern must be satisfied for it to fire, so no single one
    of their permissions is detectable by itself. Several resources inside ONE
    rule are not skipped - that also behaves as AND, and a pattern written that
    way silently fails to detect a role holding just one of them, which is a bug
    rather than a design choice.
    """
    seen = set()
    for pattern in patterns:
        if len(pattern.rules) > 1:
            continue
        for pattern_rule in pattern.rules:
            if pattern_rule.non_resource_ur_ls:
                for url in pattern_rule.non_resource_ur_ls:
                    for verb in pattern_rule.verbs or []:
                        seen.add((None, url, verb))
                continue
            groups = pattern_rule.api_groups if pattern_rule.api_groups is not None else ['']
            for group in groups:
                for resource in pattern_rule.resources or []:
                    for verb in pattern_rule.verbs or []:
                        seen.add((group, resource, verb))
    return sorted(seen, key=lambda t: (str(t[0]), t[1], t[2]))


def probe_rule(group, target, verb):
    if group is None:
        return Rule(resources=None, verbs=[verb], api_groups=None,
                    non_resource_ur_ls=[target])
    return Rule(resources=[target], verbs=[verb], api_groups=[group])


def patterns_matching(patterns, rules, kinds=(ROLE_KIND, CLUSTER_ROLE_KIND)):
    """Names of patterns that fire on these rules, for any of the given kinds."""
    hits = set()
    for kind in kinds:
        for pattern in patterns:
            if not pattern.applies_to_kind(kind):
                continue
            if are_rules_contain_other_rules(rules, pattern.rules):
                hits.add(pattern.name)
    return hits
