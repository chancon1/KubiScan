from engine.role import Role
from engine.rule import Rule
from engine.priority import get_priority_by_name
from misc.constants import *
import yaml
import os

STATIC_RISKY_ROLES = []

def set_risky_roles_from_yaml(items):
    for role in items:
        rules = []
        for rule in role['rules']:
            # A non-resource URL rule carries no 'resources' at all.
            rule_obj = Rule(resources=rule.get('resources'), verbs=rule['verbs'],
                            api_groups=rule.get('apiGroups'),
                            non_resource_ur_ls=rule.get('nonResourceURLs'))
            rules.append(rule_obj)

        STATIC_RISKY_ROLES.append(Role(role['metadata']['name'],
                                       get_priority_by_name(role['metadata']['priority']),
                                       rules,
                                       namespace=RISKY_NAMESPACE)
                                  )

with open(os.path.dirname(os.path.realpath(__file__)) + '/risky_roles.yaml', 'r') as stream:
    try:
        loaded_yaml = yaml.safe_load(stream)
        set_risky_roles_from_yaml(loaded_yaml['items'])
    except yaml.YAMLError as exc:
        print(exc)
