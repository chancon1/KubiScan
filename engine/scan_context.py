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


def is_sensitive_namespace(namespace, patterns):
    """Is this namespace covered by the configured list?

    An entry ending in '*' matches by prefix. Distributions name their platform
    namespaces from one stem - 'shturval-monitoring', 'shturval-logging' - and
    listing every one of them by hand means the list silently goes stale as soon
    as the platform grows a component. Everything else is an exact name, because
    'infra' must not quietly cover 'infra-sandbox'.
    """
    if namespace is None:
        return False
    if namespace in patterns:
        return True
    return any(pattern.endswith('*') and namespace.startswith(pattern[:-1])
               for pattern in patterns)


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


def _selector_dict(raw):
    """Normalise one LabelSelector out of whatever shape it arrived in.

    The live client hands over a V1LabelSelector, a manifest dump hands over the
    plain JSON. Reducing both to the same two lists keeps the matching below
    from having to know which it is looking at.
    """
    if raw is None:
        return {'labels': {}, 'expressions': []}
    if isinstance(raw, dict):
        match_labels = raw.get('matchLabels')
        match_expressions = raw.get('matchExpressions')
    else:
        match_labels = getattr(raw, 'match_labels', None)
        match_expressions = getattr(raw, 'match_expressions', None)

    expressions = []
    for expression in match_expressions or []:
        if isinstance(expression, dict):
            key = expression.get('key')
            operator = expression.get('operator')
            values = expression.get('values')
        else:
            key = getattr(expression, 'key', None)
            operator = getattr(expression, 'operator', None)
            values = getattr(expression, 'values', None)
        expressions.append((key, (operator or '').lower(), set(values or [])))
    return {'labels': dict(match_labels or {}), 'expressions': expressions}


def _selectors_of(raw_role):
    """Every clusterRoleSelector of an aggregated ClusterRole, normalised."""
    rule = getattr(raw_role, 'aggregation_rule', None)
    if rule is None:
        return []
    if isinstance(rule, dict):
        selectors = rule.get('clusterRoleSelectors')
    else:
        selectors = getattr(rule, 'cluster_role_selectors', None)
    return [_selector_dict(selector) for selector in selectors or []]


def _labels_match(labels, selector):
    """Kubernetes LabelSelector semantics, including the empty-selector case.

    An empty selector matches everything. That is the API server's rule, and an
    aggregated ClusterRole written that way really does collect every ClusterRole
    in the cluster, so reporting it as such is the accurate answer rather than a
    quirk to paper over.
    """
    for key, value in selector['labels'].items():
        if labels.get(key) != value:
            return False
    for key, operator, values in selector['expressions']:
        present = key in labels
        if operator == 'exists':
            if not present:
                return False
        elif operator == 'doesnotexist':
            if present:
                return False
        elif operator == 'in':
            if not present or labels[key] not in values:
                return False
        elif operator == 'notin':
            if present and labels[key] in values:
                return False
        else:
            # An operator this version does not know must not silently widen the
            # selector into a match.
            return False
    return True


class RoleFacts:
    """What the scan read off one Role or ClusterRole, before any matching."""

    def __init__(self, rules, labels=None, aggregation_selectors=None):
        self.rules = rules or []
        self.labels = labels or {}
        self.aggregation_selectors = aggregation_selectors or []


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
        # role key -> RoleFacts, filled by record_roles() as the scan reads them.
        # Chain analysis needs the rules of every role a subject holds, not only
        # of the ones that were risky on their own: a leg of an escalation chain
        # is often harmless by itself. Aggregation resolution needs the labels
        # and selectors of roles that were never risky either.
        self._roles_by_key = {}

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

    def record_roles(self, raw_roles, kind):
        """Remember every role of one kind, risky or not."""
        for raw_role in raw_roles or []:
            key = self._key(kind, raw_role.metadata.name, raw_role.metadata.namespace)
            self._roles_by_key[key] = RoleFacts(
                raw_role.rules,
                getattr(raw_role.metadata, 'labels', None),
                _selectors_of(raw_role))

    def rules_for_key(self, key):
        facts = self._roles_by_key.get(key)
        return facts.rules if facts is not None else []

    def is_key_bound(self, key):
        return any(binding.subjects for binding in self._index.get(key, []))

    def aggregation_sources(self):
        """parent ClusterRole key -> the source keys its rules are collected from.

        Kubernetes fills an aggregated ClusterRole's rules from every ClusterRole
        matching its selectors, so the parent already carries what the sources
        grant. Reporting both means reporting the same permission twice: once as
        a real grant and once as a latent definition that only exists to feed it.
        """
        parents = {}
        for key, facts in self._roles_by_key.items():
            if key[0] != CLUSTER_ROLE_KIND or not facts.aggregation_selectors:
                continue
            sources = []
            for other_key, other in self._roles_by_key.items():
                if other_key == key or other_key[0] != CLUSTER_ROLE_KIND:
                    continue
                if any(_labels_match(other.labels, selector)
                       for selector in facts.aggregation_selectors):
                    sources.append(other_key)
            if sources:
                parents[key] = sorted(sources)
        return parents

    def foldable_sources(self):
        """parent key -> sources that exist only to feed it.

        Two kinds of source are not folded away. One with a binding of its own is
        a grant somebody actually holds. One that is an aggregated ClusterRole
        itself is a composition point rather than a fragment - the built-in
        'edit' carries the label that feeds 'admin', but it has its own name, its
        own sources and its own bindings elsewhere, and burying it inside 'admin'
        would hide the role people actually reason about.
        """
        folded = {}
        for parent, sources in self.aggregation_sources().items():
            fragments = [key for key in sources
                         if not self.is_key_bound(key)
                         and not self._roles_by_key[key].aggregation_selectors]
            if fragments:
                folded[parent] = fragments
        return folded

    def iter_bindings(self):
        """(role key, binding) for every binding the scan indexed."""
        for key, bindings in self._index.items():
            for binding in bindings:
                yield key, binding

    def bindings_for(self, role):
        """Every binding that names this role, whether or not it grants anything.

        This is the enumeration a report walks. Scoring wants granting_bindings()
        instead.
        """
        return self._index.get(self._key(role.kind, role.name, role.namespace), [])

    def granting_bindings(self, role):
        """The bindings that actually hand this role to somebody.

        A RoleBinding or ClusterRoleBinding with an empty subject list is a real
        object that grants nothing at all, so no question about reach - is this
        cluster-wide, which namespaces does it touch, who holds it - may count
        it. Answering those from bindings_for() is what let a subject-less
        ClusterRoleBinding score as an active cluster-wide grant in one report
        while the event view called the same object latent.
        """
        return [binding for binding in self.bindings_for(role) if binding.subjects]

    def is_bound(self, role):
        return bool(self.granting_bindings(role))

    def is_cluster_wide(self, role):
        """Does the grant reach every namespace?

        Only a ClusterRole reached through a ClusterRoleBinding does. A
        ClusterRole referenced by a namespaced RoleBinding applies inside that
        one namespace, which is the distinction the old flat matrix missed.
        """
        if role.kind != CLUSTER_ROLE_KIND:
            return False
        return any(binding.is_cluster_wide for binding in self.granting_bindings(role))

    def is_namespaced_binding_only(self, role):
        """A ClusterRole that exists but no ClusterRoleBinding ever grants.

        Its cluster-scoped rules never take effect: binding a ClusterRole with a
        RoleBinding grants only its namespaced permissions, inside that one
        namespace.
        """
        if role.kind != CLUSTER_ROLE_KIND:
            return False
        bindings = self.granting_bindings(role)
        return bool(bindings) and not any(binding.is_cluster_wide for binding in bindings)

    def granted_namespaces(self, role):
        """Namespaces in which the grant actually applies.

        Empty when the role is unbound, and meaningless when the grant is
        cluster-wide - callers check is_cluster_wide() first.
        """
        if role.kind == ROLE_KIND:
            return {role.namespace} if self.is_bound(role) else set()
        return {binding.namespace for binding in self.granting_bindings(role)
                if not binding.is_cluster_wide and binding.namespace is not None}

    def sensitive_namespaces_hit(self, role):
        return sorted(namespace for namespace in self.granted_namespaces(role)
                      if is_sensitive_namespace(namespace, self.sensitive_namespaces))

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
        for binding in self.granting_bindings(role):
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
        for binding in self.granting_bindings(role):
            for subject in binding.subjects or []:
                if subject.kind == GROUP_KIND and subject.name in EVERYONE_GROUPS:
                    found.add(subject.name)
        return sorted(found)

    def scoped_to(self, *bindings):
        """A view of this context in which a role has exactly these bindings.

        A ClusterRole reached both by a ClusterRoleBinding and by a namespaced
        RoleBinding is two different grants of different severity. The role-level
        report shows the worst of them; a single binding is scored through this.

        A binding with no subjects needs no special view: granting_bindings()
        drops it here exactly as it drops it at the role level, so it scores as
        the latent definition it is.
        """
        return FixedBindingsContext(self, list(bindings))

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


class FixedBindingsContext(ScanContext):
    """ScanContext whose binding lookup is a fixed list, for narrower scoring.

    Used for one binding of a role, and for the set of bindings through which
    one subject reaches a permission. Everything except the lookup is shared
    with the parent, so the sensitive-namespace list and the privileged
    service-account map stay identical to the role-level view.
    """

    # Deliberately does not call super().__init__: the parent's index and
    # namespace sets are reused as-is rather than rebuilt.
    def __init__(self, parent, bindings):
        self.sensitive_namespaces = parent.sensitive_namespaces
        self._index = parent._index
        self._roles_by_key = parent._roles_by_key
        self.privileged_service_accounts = parent.privileged_service_accounts
        self.privileged_sa_known = parent.privileged_sa_known
        self._bindings = list(bindings)

    def bindings_for(self, role):
        return self._bindings
