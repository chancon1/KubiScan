import os

import yaml

from engine.priority import Priority
from misc.constants import *

SENSITIVE_NAMESPACES_FILE = 'sensitive_namespaces.yaml'

# Binding a role to either of these hands it to every user of the cluster.
# 'system:anonymous' is deliberately not here: it is a single identity, and the
# broad case is already covered by system:unauthenticated. Treating it as
# "everyone" would flag the kubeadm cluster-info grant, which is a documented
# part of how bootstrapping works.
EVERYONE_GROUPS = frozenset(['system:authenticated', 'system:unauthenticated'])


def load_sensitive_namespaces():
    """Read the shipped list of namespaces that raise a finding by one level."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))),
                        SENSITIVE_NAMESPACES_FILE)
    try:
        with open(path, 'r') as stream:
            loaded = yaml.safe_load(stream) or {}
    except (IOError, OSError, yaml.YAMLError):
        return set()

    namespaces = set()
    for group in (loaded.get('groups') or {}).values():
        namespaces.update(group or [])
    return namespaces


# Set once from the command line; every context built afterwards uses it.
_configured_sensitive_namespaces = None


def configure_sensitive_namespaces(replace=None, extra=None):
    """Override or extend the shipped list, from --sensitive-namespaces[-add]."""
    global _configured_sensitive_namespaces
    namespaces = set(replace) if replace is not None else load_sensitive_namespaces()
    if extra:
        namespaces |= set(extra)
    _configured_sensitive_namespaces = namespaces


def effective_sensitive_namespaces():
    if _configured_sensitive_namespaces is not None:
        return _configured_sensitive_namespaces
    return load_sensitive_namespaces()


class BoundBinding:
    """A RoleBinding or ClusterRoleBinding pointing at a role we scanned."""

    def __init__(self, kind, name, namespace, subjects, time=None):
        self.kind = kind
        self.name = name
        self.namespace = namespace
        self.subjects = subjects or []
        self.time = time

    @property
    def is_cluster_wide(self):
        return self.kind == CLUSTER_ROLE_BINDING_KIND


class ScanContext:
    """Everything a finding needs to know about the cluster around it.

    Built once per scan. The binding index is the important part: whether a
    permission is dangerous depends on where it was actually granted, and that
    is knowable only by looking at the bindings before scoring rather than
    after, which is where the report used to fetch them.
    """

    def __init__(self, role_bindings, cluster_role_bindings, sensitive_namespaces=None):
        self.sensitive_namespaces = (sensitive_namespaces if sensitive_namespaces is not None
                                     else effective_sensitive_namespaces())
        self._index = {}
        self._build_index(role_bindings, cluster_role_bindings)
        # namespace -> {service account names}, filled by build_privileged_sa_map()
        # once the first scoring pass knows which accounts are dangerous in
        # their own right.
        self.privileged_service_accounts = {}
        self.privileged_sa_known = False

    @classmethod
    def build(cls, sensitive_namespaces=None):
        from api.config import Config
        role_bindings = Config.api_client.list_role_binding_for_all_namespaces()
        cluster_role_bindings = Config.api_client.list_cluster_role_binding()
        return cls(role_bindings.items, cluster_role_bindings, sensitive_namespaces)

    @staticmethod
    def _key(kind, name, namespace):
        # A ClusterRole is one object cluster-wide, so its namespace never takes
        # part in the key. A Role only exists inside its own namespace, and two
        # roles of the same name in different namespaces are unrelated.
        if kind == CLUSTER_ROLE_KIND:
            return (CLUSTER_ROLE_KIND, name, None)
        return (ROLE_KIND, name, namespace)

    def _build_index(self, role_bindings, cluster_role_bindings):
        for rb in role_bindings or []:
            ref = rb.role_ref
            if ref is None:
                continue
            key = self._key(ref.kind or ROLE_KIND, ref.name, rb.metadata.namespace)
            self._index.setdefault(key, []).append(
                BoundBinding(ROLE_BINDING_KIND, rb.metadata.name, rb.metadata.namespace,
                             rb.subjects, rb.metadata.creation_timestamp))

        for crb in cluster_role_bindings or []:
            ref = crb.role_ref
            if ref is None:
                continue
            # A ClusterRoleBinding can only reference a ClusterRole.
            key = self._key(CLUSTER_ROLE_KIND, ref.name, None)
            self._index.setdefault(key, []).append(
                BoundBinding(CLUSTER_ROLE_BINDING_KIND, crb.metadata.name, None, crb.subjects,
                             crb.metadata.creation_timestamp))

    def bindings_for(self, role):
        return self._index.get(self._key(role.kind, role.name, role.namespace), [])

    def is_bound(self, role):
        return bool(self.bindings_for(role))

    def is_cluster_wide(self, role):
        """Does the grant reach every namespace?

        Only a ClusterRole reached through a ClusterRoleBinding does. A
        ClusterRole referenced by a namespaced RoleBinding applies inside that
        one namespace, which is the distinction the old flat matrix missed.
        """
        if role.kind != CLUSTER_ROLE_KIND:
            return False
        return any(binding.is_cluster_wide for binding in self.bindings_for(role))

    def is_namespaced_binding_only(self, role):
        """A ClusterRole that exists but no ClusterRoleBinding ever references.

        Its cluster-scoped rules never take effect: binding a ClusterRole with a
        RoleBinding grants only its namespaced permissions, inside that one
        namespace.
        """
        if role.kind != CLUSTER_ROLE_KIND:
            return False
        bindings = self.bindings_for(role)
        return bool(bindings) and not any(binding.is_cluster_wide for binding in bindings)

    def granted_namespaces(self, role):
        """Namespaces in which the grant actually applies.

        Empty when the role is unbound, and meaningless when the grant is
        cluster-wide - callers check is_cluster_wide() first.
        """
        if role.kind == ROLE_KIND:
            return {role.namespace} if self.is_bound(role) else set()
        return {binding.namespace for binding in self.bindings_for(role)
                if not binding.is_cluster_wide and binding.namespace is not None}

    def sensitive_namespaces_hit(self, role):
        return sorted(self.granted_namespaces(role) & self.sensitive_namespaces)

    def build_privileged_sa_map(self, scored_roles):
        """Record which namespaces host a service account that is already critical.

        This is what makes "can create a pod" meaningful: creating a pod lets
        you name any service account of that namespace as its identity, so the
        permission is worth exactly as much as the best identity standing next
        to it. Built from the first scoring pass, which never consults this map,
        so there is no circularity.
        """
        self.privileged_service_accounts = {}
        for role in scored_roles:
            if role.priority != Priority.CRITICAL:
                continue
            for namespace, name in self._service_account_subjects(role):
                self.privileged_service_accounts.setdefault(namespace, set()).add(name)
        self.privileged_sa_known = True

    def _service_account_subjects(self, role):
        """(namespace, name) of every service account bound to this role."""
        found = set()
        for binding in self.bindings_for(role):
            for subject in binding.subjects or []:
                if subject.kind != SERVICEACCOUNT_KIND:
                    continue
                namespace = subject.namespace or binding.namespace
                if namespace is not None:
                    found.add((namespace, subject.name))
        return found

    def bound_to_everyone(self, role):
        """Groups on this role's bindings that mean 'every user of the cluster'."""
        found = set()
        for binding in self.bindings_for(role):
            for subject in binding.subjects or []:
                if subject.kind == GROUP_KIND and subject.name in EVERYONE_GROUPS:
                    found.add(subject.name)
        return sorted(found)

    def scoped_to(self, binding):
        """A view of this context in which a role has exactly one binding.

        A ClusterRole reached both by a ClusterRoleBinding and by a namespaced
        RoleBinding is two different grants of different severity. The role-level
        report shows the worst of them; a single binding is scored through this.
        """
        return SingleBindingContext(self, binding)

    def without_bindings(self):
        """A view in which the role has no effective grant.

        Used for a RoleBinding/ClusterRoleBinding whose subjects list is empty.
        Such an object exists, but Kubernetes grants its role to nobody, so it
        must score like a latent role rather than an active cluster-wide grant.
        """
        return NoBindingContext(self)

    def reaches_privileged_sa(self, role):
        """Can this grant borrow an identity better than the one it already has?

        Returns the accounts it can borrow, not a sentence about them: how that
        reads in a report is the report's business.

        Service accounts already bound to this very role are excluded. An
        operator whose own account holds both "create pods" and a cluster-wide
        permission is not escalating by running a pod as itself - it is using
        rights it already had, and counting that was pure noise.
        """
        if not self.privileged_sa_known:
            return False, None

        own = self._service_account_subjects(role)
        if self.is_cluster_wide(role):
            namespaces = sorted(self.privileged_service_accounts)
        else:
            namespaces = sorted(self.granted_namespaces(role)
                                & set(self.privileged_service_accounts))

        reachable = []
        for namespace in namespaces:
            others = sorted(name for name in self.privileged_service_accounts[namespace]
                            if (namespace, name) not in own)
            reachable += ['{0}/{1}'.format(namespace, name) for name in others]

        if not reachable:
            return False, None
        shown = ', '.join(reachable[:3])
        if len(reachable) > 3:
            shown += ' (+{0} more)'.format(len(reachable) - 3)
        return True, shown


class SingleBindingContext(ScanContext):
    """ScanContext restricted to one binding, for per-binding scoring.

    Everything except the binding lookup is shared with the parent, so the
    sensitive-namespace list and the privileged service-account map stay
    identical between the role-level and binding-level views.
    """

    # Deliberately does not call super().__init__: the parent's index and
    # namespace sets are reused as-is rather than rebuilt.
    def __init__(self, parent, binding):
        self.sensitive_namespaces = parent.sensitive_namespaces
        self._index = parent._index
        self.privileged_service_accounts = parent.privileged_service_accounts
        self.privileged_sa_known = parent.privileged_sa_known
        self._binding = binding

    def bindings_for(self, role):
        return [self._binding]


class NoBindingContext(SingleBindingContext):
    """Shared scan context with an intentionally empty binding lookup."""

    def __init__(self, parent):
        self.sensitive_namespaces = parent.sensitive_namespaces
        self._index = parent._index
        self.privileged_service_accounts = parent.privileged_service_accounts
        self.privileged_sa_known = parent.privileged_sa_known
        self._binding = None

    def bindings_for(self, role):
        return []
