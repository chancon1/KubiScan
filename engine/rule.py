# It is also possible to use client.V1PolicyRule(api_groups, non_resource_ur_ls, resource_names, resources, verbs)

# Verbs whose request never addresses one object, whatever the resource. RBAC
# reads the object name from the request path, and a collection request has none
# to read.
COLLECTION_VERBS = frozenset(['list', 'watch', 'deletecollection'])


def carries_object_name(verb, resources):
    """Can a request for this verb name an object a 'resourceNames' rule matches?

    This is what a name-pinned rule actually grants, and the answer differs by
    verb:

      - a collection request ('list', 'watch', 'deletecollection') never names
        one object, so a pinned rule grants it nothing at all;
      - a 'create' of a top-level resource carries no name either: the name is
        in the request body, which the authorizer never reads. Pinning it grants
        nothing;
      - a 'create' of a SUBRESOURCE does carry one, because the parent's name is
        in the path, as in 'serviceaccounts/<name>/token'. Pinning that is how
        the documentation scopes token minting to a single account, and the API
        server enforces it;
      - every other verb ('get', 'update', 'delete', 'use', 'bind', 'escalate',
        'impersonate', 'approve', ...) addresses one named object by definition.

    A wildcard verb covers 'get' among others, so it carries a name too, and
    what it grants stays confined to the pinned objects.
    """
    verb = (verb or '').lower()
    if verb in COLLECTION_VERBS:
        return False
    if verb == 'create':
        return any('/' in resource for resource in resources or [])
    return True


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