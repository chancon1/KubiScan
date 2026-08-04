import os

import yaml

from engine.priority import get_priority_by_name
from engine.risky_pattern import RiskyPattern, CLUSTER_SCOPE, NAMESPACED_SCOPE
from engine.rule import Rule
from misc.constants import *

STATIC_RISKY_ROLES = []

VALID_SCOPES = (CLUSTER_SCOPE, NAMESPACED_SCOPE)


def _build_rules(raw_rules, any_api_group=False):
    rules = []
    for rule in raw_rules:
        # A non-resource URL rule carries no 'resources' at all.
        rules.append(Rule(resources=rule.get('resources'),
                          verbs=rule['verbs'],
                          api_groups=rule.get('apiGroups'),
                          non_resource_ur_ls=rule.get('nonResourceURLs'),
                          any_api_group=any_api_group))
    return rules


def _resolve_modifiers(metadata, profiles):
    """Profile first, then any inline overrides on the pattern itself."""
    modifiers = {}
    profile_name = metadata.get('profile')
    if profile_name:
        if profile_name not in profiles:
            raise ValueError("Unknown profile '{0}' on pattern '{1}'".format(
                profile_name, metadata.get('name')))
        modifiers.update(profiles[profile_name] or {})
    modifiers.update(metadata.get('modifiers') or {})
    return modifiers


def set_risky_roles_from_yaml(items, profiles=None):
    profiles = profiles or {}
    for entry in items:
        metadata = entry['metadata']
        name = metadata['name']

        scope = metadata.get('scope', NAMESPACED_SCOPE)
        if scope not in VALID_SCOPES:
            raise ValueError("Pattern '{0}' has unknown scope '{1}'".format(name, scope))

        applies_to = metadata.get('appliesTo') or [ROLE_KIND, CLUSTER_ROLE_KIND]
        unknown = [kind for kind in applies_to if kind not in (ROLE_KIND, CLUSTER_ROLE_KIND)]
        if unknown:
            raise ValueError("Pattern '{0}' has unknown appliesTo entries: {1}".format(
                name, ', '.join(unknown)))

        any_api_group = bool(metadata.get('matchesAnyApiGroup', False))
        STATIC_RISKY_ROLES.append(RiskyPattern(
            name,
            get_priority_by_name(metadata['priority']),
            _build_rules(entry['rules'], any_api_group),
            resource_scope=scope,
            applies_to=applies_to,
            modifiers=_resolve_modifiers(metadata, profiles),
            category=metadata.get('category'),
            any_api_group=any_api_group,
        ))


with open(os.path.dirname(os.path.realpath(__file__)) + '/risky_roles.yaml', 'r') as stream:
    try:
        loaded_yaml = yaml.safe_load(stream)
        set_risky_roles_from_yaml(loaded_yaml['items'], loaded_yaml.get('profiles'))
    except yaml.YAMLError as exc:
        print(exc)
