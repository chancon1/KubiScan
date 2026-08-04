# It is also possible to use client.V1PolicyRule(api_groups, non_resource_ur_ls, resource_names, resources, verbs)
class Rule:
    def __init__(self, verbs, resources, resource_names=None, api_groups=None,
                 non_resource_ur_ls=None, any_api_group=False):
        self.verbs = verbs
        self.resources = resources
        self.resource_names = resource_names
        self.api_groups = api_groups
        # RBAC keeps non-resource URLs in their own field, never under 'resources'.
        self.non_resource_ur_ls = non_resource_ur_ls
        # Pattern rules only. Normally a pattern asking for apiGroups ["*"] wants
        # a role that is itself group-unrestricted. A pattern setting this flag
        # instead means "whichever single group this happens to be", which is how
        # total control of one vendor's API group gets detected without having to
        # enumerate every group that could exist.
        self.any_api_group = any_api_group