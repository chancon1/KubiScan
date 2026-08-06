import requests

from engine.role import Role
from engine.priority import Priority
from engine.finding import Finding, RuleMatch
from engine.rule import carries_object_name
from engine.scan_context import BoundBinding, ScanContext
from engine.scoring import score_finding, score_findings_for_scope, highest_priority
from static_risky_roles import STATIC_RISKY_ROLES
from engine.role_binding import RoleBinding
from kubernetes.stream import stream
from engine.pod import Pod
from engine.container import Container
import json
from api import api_client
from engine.subject import Subject
from misc.constants import *
from kubernetes.client.rest import ApiException
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from api.config import Config

# region - Roles and ClusteRoles

list_of_service_accounts = []


def _non_resource_url_matches(source_url, risky_url):
    """Does a granted non-resource URL cover the one a pattern looks for?

    RBAC allows a trailing '*' on either side ('/debug/*'), so compare by prefix
    whenever one is present and fall back to equality otherwise.
    """
    source_prefix = source_url[:-1] if source_url.endswith('*') else None
    risky_prefix = risky_url[:-1] if risky_url.endswith('*') else None

    if source_prefix is not None and risky_prefix is not None:
        return source_prefix.startswith(risky_prefix) or risky_prefix.startswith(source_prefix)
    if source_prefix is not None:
        return risky_url.startswith(source_prefix)
    if risky_prefix is not None:
        return source_url.startswith(risky_prefix)
    return source_url == risky_url


def do_non_resource_urls_contain(source_rule, risky_urls):
    source_urls = getattr(source_rule, 'non_resource_ur_ls', None) or []
    return any(_non_resource_url_matches(source_url, risky_url)
               for risky_url in risky_urls
               for source_url in source_urls)


def _resource_matches(source_resources, risky_resource):
    """Whether a granted resource list covers one resource of a pattern.

    Understands subresource wildcards in both directions: a pattern asking for
    'userextras/*' is satisfied by 'userextras/scopes', and a role granting
    'pods/*' satisfies a pattern asking for 'pods/exec'.
    """
    if '*' in source_resources or risky_resource in source_resources:
        return True
    if risky_resource.endswith('/*'):
        prefix = risky_resource[:-1]
        if any(resource.startswith(prefix) for resource in source_resources):
            return True
    return any(resource.endswith('/*') and risky_resource.startswith(resource[:-1])
               for resource in source_resources)


def _matched_verbs(source_rule, risky_rule):
    """Which of the pattern's verbs the source rule actually grants.

    A source rule holding "*" grants every verb the pattern asks about, so the
    full pattern list is what got granted. This list is not cosmetic: scoring
    reads it to decide whether a 'resourceNames' restriction is real, and a
    pinned rule does not grant every verb it lists.
    """
    source_verbs = source_rule.verbs or []
    source_has_wildcard = '*' in source_verbs
    matched = []
    for verb in risky_rule.verbs or []:
        if verb == '*':
            # A pattern listing "*" asks for unrestricted verb access itself,
            # and only a source rule that also says "*" provides it.
            if source_has_wildcard:
                matched.append('*')
            continue
        if source_has_wildcard or verb in source_verbs:
            matched.append(verb)
    return matched


def is_rule_contains_risky_rule(source_rule, risky_rule):
    """Return a RuleMatch when 'source_rule' grants what 'risky_rule' describes.

    Returns None when it does not, so callers get the matched verbs and the
    source rule itself rather than a bare boolean.
    """
    # Verb matching: OR logic - match if the source rule contains ANY of the
    # pattern's verbs. A source rule with verbs=["*"] covers all of them.
    matched_verbs = _matched_verbs(source_rule, risky_rule)
    if not matched_verbs:
        return None

    # A non-resource URL pattern is matched against its own field; such rules
    # carry neither apiGroups nor resources, so the checks below do not apply.
    risky_non_resource_urls = getattr(risky_rule, 'non_resource_ur_ls', None)
    if risky_non_resource_urls:
        if do_non_resource_urls_contain(source_rule, risky_non_resource_urls):
            return RuleMatch(source_rule, risky_rule, matched_verbs, [])
        return None

    # apiGroups matching: at least one apiGroup from the pattern must be covered
    # by the source rule, and a source rule holding "*" covers all of them.
    #
    # A pattern asking for ["*"] is asking for group-unrestricted access
    # specifically, so only a source rule that also says "*" satisfies it. That
    # distinction matters: 'apiGroups: [constraints.gatekeeper.sh], resources:
    # ["*"]' is every resource of one group, not every resource of the cluster,
    # and treating the two alike let the wildcard patterns swallow it.
    source_api_groups = getattr(source_rule, 'api_groups', None) or []
    if risky_rule.api_groups is not None:
        if "*" in risky_rule.api_groups:
            if not getattr(risky_rule, 'any_api_group', False) \
                    and "*" not in source_api_groups:
                return None
        elif "*" not in source_api_groups:
            if not any(ag in source_api_groups for ag in risky_rule.api_groups):
                return None

    if source_rule.resources is None:
        return None

    # Resource matching: ALL of the pattern's resources must be present in the
    # source rule. A source rule with resources=["*"] covers all of them.
    for resource in risky_rule.resources or []:
        if not _resource_matches(source_rule.resources, resource):
            return None

    matched_resources = list(risky_rule.resources or [])

    # A 'resourceNames' rule only authorizes requests that name one of those
    # objects. A verb whose request carries no name therefore gets nothing from
    # such a rule - it is not granted broadly, it is not granted at all - so it
    # must leave the match rather than sit in it looking unrestricted. If that
    # empties the match, the pattern did not fire.
    if getattr(source_rule, 'resource_names', None):
        matched_verbs = [verb for verb in matched_verbs
                         if carries_object_name(verb, matched_resources)]
        if not matched_verbs:
            return None

    return RuleMatch(source_rule, risky_rule, matched_verbs, matched_resources)


def get_current_version(certificate_authority_file=None, client_certificate_file=None, client_key_file=None, host=None):
    if host is None:
        version = api_client.api_version.get_code().git_version
        return version.replace('v', "")
    else:
        if certificate_authority_file is None and client_certificate_file is None and client_key_file is None:
            response = requests.get(host + '/version', verify=False)
            if response.status_code != 200:
                print(response.text)
                return None
            else:
                return response.json()["gitVersion"].replace('v', "")
        if certificate_authority_file is not None and client_certificate_file is not None and client_key_file is not None:
            response = requests.get(host + '/version', cert=(client_certificate_file, client_key_file),
                                    verify=certificate_authority_file)
            if response.status_code != 200:
                print(response.text)
                return None
            else:
                return response.json()["gitVersion"].replace('v', "")
        if certificate_authority_file is None or client_certificate_file is None or client_key_file is None or host is None:
            print("Please provide certificate authority file path, client certificate file path,"
                  " client key file path and host address")
            return None
        response = requests.get(host + '/version', cert=(client_certificate_file, client_key_file),
                                verify=certificate_authority_file)
        if response.status_code != 200:
            print(response.text)
            return None
        else:
            return response.json()["gitVersion"].replace('v', "")




def are_rules_contain_other_rules(source_rules, target_rules):
    """Return the RuleMatch list when every target rule is satisfied, else [].

    A pattern holding more than one rule behaves as AND: all of its rules must
    be matched, possibly by different rules of the source role. That is what
    makes escalation-chain patterns ("create pods" AND "get secrets") work.

    Every rule that satisfies a given pattern rule is kept, not just the first.
    Stopping at the first one answered "does this match" correctly but left
    scoring looking at an arbitrary rule, and whether a grant is restricted is a
    fact about all the ways the role hands it out.
    """
    if not (target_rules and source_rules):
        return []
    matches = []
    for target_rule in target_rules:
        granting = [match for match in
                    (is_rule_contains_risky_rule(source_rule, target_rule)
                     for source_rule in source_rules)
                    if match is not None]
        if not granting:
            return []
        matches.append(RuleMatch.merged(granting))
    return matches


def evaluate_role(role, kind):
    """Every pattern this role matches, unscored.

    Context-free by design: the same role yields the same findings no matter how
    it is bound. Turning them into severities is scoring's job, and it needs the
    whole cluster to do it.
    """
    findings = []
    for pattern in STATIC_RISKY_ROLES:
        if not pattern.applies_to_kind(kind):
            continue
        matches = are_rules_contain_other_rules(role.rules, pattern.rules)
        if not matches:
            continue
        finding = Finding(pattern, matches)
        if pattern.subsumes_all:
            # Nothing more specific can add information once this matched.
            return [finding]
        findings.append(finding)
    return findings


def _score_role(role, ctx, second_pass=False):
    for finding in role.findings:
        score_finding(finding, role, ctx, second_pass)
    role.priority = highest_priority(role.findings)


def find_risky_roles(roles, kind, ctx=None):
    """Build scored Role objects for whichever raw roles match a pattern."""
    if ctx is None:
        ctx = ScanContext.build()
    risky_roles = []
    for role in roles:
        findings = evaluate_role(role, kind)
        if not findings:
            continue
        risky_role = Role(role.metadata.name, Priority.NONE, rules=role.rules,
                          namespace=role.metadata.namespace, kind=kind,
                          time=role.metadata.creation_timestamp, findings=findings)
        _score_role(risky_role, ctx)
        risky_roles.append(risky_role)
    return risky_roles


def get_roles_by_kind(kind):
    all_roles = []
    if kind == ROLE_KIND:
        #all_roles = api_client.RbacAuthorizationV1Api.list_role_for_all_namespaces()
        all_roles = Config.api_client.list_roles_for_all_namespaces()
    else:
        #all_roles = api_client.RbacAuthorizationV1Api.list_cluster_role()
        #all_roles = api_client.api_temp.list_cluster_role()
        all_roles = Config.api_client.list_cluster_role()
    return all_roles


# Roles and ClusterRoles are always scanned together, because scoring one needs
# to know about the other: "can create a pod" is only critical when a critical
# service account stands next to it, whichever kind of role granted that account
# its power. The result is memoised so that the several report switches of a
# single run do not each re-read the whole cluster.
_scan_cache = None


def scan_roles_and_clusterroles(force=False):
    """Full two-pass scan. Returns (risky_roles, context)."""
    global _scan_cache
    if _scan_cache is not None and not force:
        return _scan_cache

    ctx = ScanContext.build()

    risky_roles = []
    for kind in (ROLE_KIND, CLUSTER_ROLE_KIND):
        all_roles = get_roles_by_kind(kind)
        if all_roles is not None:
            # Recorded before the risky ones are picked out: a subject can
            # complete an escalation chain out of roles that are individually
            # dull, and those rules are needed to see it.
            ctx.record_roles(all_roles.items, kind)
            risky_roles += find_risky_roles(all_roles.items, kind, ctx)

    # The first pass scored everything except the one modifier that has to know
    # which service accounts are already critical. Build that map from its
    # result - it never consults the map itself, so there is no circularity -
    # and let the affected findings settle.
    ctx.build_privileged_sa_map(risky_roles)
    for risky_role in risky_roles:
        _score_role(risky_role, ctx, second_pass=True)
        risky_role.bound_service_accounts = describe_bound_subjects(risky_role, ctx)

    _scan_cache = (risky_roles, ctx)
    return _scan_cache


def reset_scan_cache():
    global _scan_cache
    _scan_cache = None


def get_risky_roles_and_clusterroles():
    return scan_roles_and_clusterroles()[0]


def get_risky_roles():
    return [role for role in get_risky_roles_and_clusterroles() if role.kind == ROLE_KIND]


def get_risky_clusterroles():
    return [role for role in get_risky_roles_and_clusterroles() if role.kind == CLUSTER_ROLE_KIND]


# endregion - Roles and ClusteRoles


def describe_bound_subjects(role, ctx):
    """Return list of strings describing the subjects bound to the given role.

    Users and Groups are reported alongside service accounts: a risky role
    granted to a group such as 'system:authenticated' is the most severe finding
    there is, and listing only service accounts left that column empty.

    Format:
      - "sa-name@sa-namespace [SA NS] (via RoleBinding: rb-namespace [RoleBinding NS]/rb-name [RoleBinding name])"
      - "sa-name@sa-namespace [SA NS] (via ClusterRoleBinding: crb-name [ClusterRoleBinding name])"
      - "subject-name [Group] (via ClusterRoleBinding: crb-name [ClusterRoleBinding name])"
    Works with both live-cluster and static-file modes.
    """
    result = []
    for binding in ctx.bindings_for(role):
        if binding.is_cluster_wide:
            via = "ClusterRoleBinding: {name} [ClusterRoleBinding name]".format(name=binding.name)
            default_namespace = None
        else:
            via = "RoleBinding: {ns} [RoleBinding NS]/{name} [RoleBinding name]".format(
                ns=binding.namespace or 'Unknown', name=binding.name)
            default_namespace = binding.namespace or 'Unknown'

        for subject in binding.subjects or []:
            if subject.kind == SERVICEACCOUNT_KIND:
                result.append("{sa}@{ns} [SA NS] (via {via})".format(
                    sa=subject.name,
                    ns=subject.namespace or default_namespace,
                    via=via))
            else:
                result.append("{name} [{kind}] (via {via})".format(
                    name=subject.name, kind=subject.kind, via=via))
    return result

# region - RoleBindings and ClusterRoleBindings

def get_role_referenced_by_binding(risky_roles, rolebinding):
    """Return the risky role a binding actually points at, or None.

    Matching on the name alone is not enough: a Role and a ClusterRole may share
    a name, and a namespaced Role only applies inside its own namespace. Without
    both checks a binding to a harmless Role inherits the priority of its
    same-named ClusterRole.
    """
    role_ref = rolebinding.role_ref
    for risky_role in risky_roles:
        if role_ref.name != risky_role.name:
            continue
        if role_ref.kind is not None and role_ref.kind != risky_role.kind:
            continue
        if risky_role.kind == ROLE_KIND and rolebinding.metadata.namespace != risky_role.namespace:
            continue
        return risky_role
    return None


def is_risky_rolebinding(risky_roles, rolebinding):
    risky_role = get_role_referenced_by_binding(risky_roles, rolebinding)
    if risky_role is None:
        return False, Priority.LOW
    return True, risky_role.priority


def findings_for_binding(risky_role, rolebinding, kind, ctx):
    """Score a role's findings for the scope of one specific binding.

    The role-level priority is the worst case across every binding it has. A
    single binding is usually narrower than that: a ClusterRole granting
    'create clusterrolebindings' is critical when a ClusterRoleBinding hands it
    out, and inert when only a namespaced RoleBinding does.

    The findings come back as copies, so the binding report can show the
    arithmetic behind its own verdict - which is the only place that verdict is
    explained - without disturbing the role-level one.
    """
    scoped = ctx.scoped_to(BoundBinding(kind, rolebinding.metadata.name,
                                        rolebinding.metadata.namespace,
                                        rolebinding.subjects,
                                        rolebinding.metadata.creation_timestamp))
    return score_findings_for_scope(risky_role.findings, risky_role, scoped, second_pass=True)


def find_risky_rolebindings_or_clusterrolebindings(risky_roles, rolebindings, kind, ctx=None):
    if ctx is None:
        ctx = scan_roles_and_clusterroles()[1]
    risky_rolebindings = []
    for rolebinding in rolebindings:
        risky_role = get_role_referenced_by_binding(risky_roles, rolebinding)
        if risky_role is not None:
            findings = findings_for_binding(risky_role, rolebinding, kind, ctx)
            risky_rolebindings.append(RoleBinding(rolebinding.metadata.name,
                                                  highest_priority(findings),
                                                  namespace=rolebinding.metadata.namespace,
                                                  kind=kind, subjects=rolebinding.subjects,
                                                  time=rolebinding.metadata.creation_timestamp,
                                                  role_ref=risky_role,
                                                  findings=findings))
    return risky_rolebindings


def get_rolebinding_by_kind_all_namespaces(kind):
    all_roles = []
    if kind == ROLE_BINDING_KIND:
        all_roles = Config.api_client.list_role_binding_for_all_namespaces()
    # else:
    # TODO: check if it was fixed
    # all_roles = api_client.RbacAuthorizationV1Api.list_cluster_role_binding()

    return all_roles


def get_all_risky_rolebinding():
    all_risky_roles, ctx = scan_roles_and_clusterroles()

    risky_rolebindings = get_risky_rolebindings(all_risky_roles, ctx)
    risky_clusterrolebindings = get_risky_clusterrolebindings(all_risky_roles, ctx)

    risky_rolebindings_and_clusterrolebindings = risky_clusterrolebindings + risky_rolebindings
    return risky_rolebindings_and_clusterrolebindings


def get_risky_rolebindings(all_risky_roles=None, ctx=None):
    if all_risky_roles is None or ctx is None:
        all_risky_roles, ctx = scan_roles_and_clusterroles()
    all_rolebindings = get_rolebinding_by_kind_all_namespaces(ROLE_BINDING_KIND)
    risky_rolebindings = find_risky_rolebindings_or_clusterrolebindings(all_risky_roles, all_rolebindings.items,
                                                                        ROLE_BINDING_KIND, ctx)

    return risky_rolebindings


def get_risky_clusterrolebindings(all_risky_roles=None, ctx=None):
    if all_risky_roles is None or ctx is None:
        all_risky_roles, ctx = scan_roles_and_clusterroles()
    # Cluster doesn't work.
    # https://github.com/kubernetes-client/python/issues/577 - when it will be solve, can remove the comments
    # all_clusterrolebindings = api_client.RbacAuthorizationV1Api.list_cluster_role_binding()
    all_clusterrolebindings = Config.api_client.list_cluster_role_binding()
    # risky_clusterrolebindings = find_risky_rolebindings(all_risky_roles, all_clusterrolebindings.items, "ClusterRoleBinding")
    risky_clusterrolebindings = find_risky_rolebindings_or_clusterrolebindings(all_risky_roles, all_clusterrolebindings,
                                                                               CLUSTER_ROLE_BINDING_KIND, ctx)
    return risky_clusterrolebindings


# endregion - RoleBindings and ClusterRoleBindings

# region- Risky Users

def get_all_risky_subjects():
    all_risky_users = []
    all_risky_rolebindings = get_all_risky_rolebinding()
    passed_users = {}
    for risky_rolebinding in all_risky_rolebindings:

        # In case 'risky_rolebinding.subjects' is 'None', 'or []' will prevent an exception.
        for user in risky_rolebinding.subjects or []:
            # Default the namespace before building the key, otherwise the same
            # service account is counted twice: once as '...None' and once as
            # '...<namespace>' depending on how each binding spelled it out.
            if user.namespace is None and (user.kind).lower() == "serviceaccount":
                user.namespace = risky_rolebinding.namespace

            unique_name = ''.join((user.kind, user.name, str(user.namespace)))
            existing = passed_users.get(unique_name)
            if existing is None:
                subject = Subject(user, risky_rolebinding.priority)
                if risky_rolebinding.role_ref is not None:
                    subject.roles.append(risky_rolebinding.role_ref)
                passed_users[unique_name] = subject
                all_risky_users.append(subject)
                continue

            # A subject is as risky as the worst role bound to it, not as the
            # first binding the API happened to return.
            if risky_rolebinding.priority.value > existing.priority.value:
                existing.priority = risky_rolebinding.priority
            if risky_rolebinding.role_ref is not None and risky_rolebinding.role_ref not in existing.roles:
                existing.roles.append(risky_rolebinding.role_ref)

    return all_risky_users


# endregion - Risky Users

# region- Risky Pods

'''
Example of JWT token decoded:
{
	'kubernetes.io/serviceaccount/service-account.uid': '11a8e2a1-6f07-11e8-8d52-000c2904e34b',
	 'iss': 'kubernetes/serviceaccount',
	 'sub': 'system:serviceaccount:default:myservice',
	 'kubernetes.io/serviceaccount/namespace': 'default',
	 'kubernetes.io/serviceaccount/secret.name': 'myservice-token-btwvr',
	 'kubernetes.io/serviceaccount/service-account.name': 'myservice'
 }
'''


def pod_exec_read_token(pod, container_name, path):
    cat_command = 'cat ' + path
    exec_command = ['/bin/sh',
                    '-c',
                    cat_command]
    resp = ''
    try:
        resp = stream(api_client.CoreV1Api.connect_post_namespaced_pod_exec, pod.metadata.name, pod.metadata.namespace,
                      command=exec_command, container=container_name,
                      stderr=False, stdin=False,
                      stdout=True, tty=False)
    except ApiException as e:
        print("Exception when calling api_client.CoreV1Api->connect_post_namespaced_pod_exec: %s\n" % e)
        print('{0}, {1}'.format(pod.metadata.name, pod.metadata.namespace))

    return resp


def pod_exec_read_token_two_paths(pod, container_name):
    result = pod_exec_read_token(pod, container_name, '/run/secrets/kubernetes.io/serviceaccount/token')
    if result == '':
        result = pod_exec_read_token(pod, container_name, '/var/run/secrets/kubernetes.io/serviceaccount/token')
    return result


def get_jwt_token_from_container(pod, container_name):
    resp = pod_exec_read_token_two_paths(pod, container_name)

    token_body = ''
    if resp != '' and not resp.startswith('OCI'):
        from engine.jwt_token import decode_jwt_token_data
        decoded_data = decode_jwt_token_data(resp)
        if decoded_data is not None and decoded_data != '':
            try:
                token_body = json.loads(decoded_data)
            except json.JSONDecodeError as e:
                print(f"Error decoding JWT token for container {container_name} in pod {pod.metadata.name}: {e}")
    
    return token_body, resp


def is_same_user(a_username, a_namespace, b_username, b_namespace):
    return (a_username == b_username and a_namespace == b_namespace)


def get_risky_user_from_container(jwt_body, risky_users):
    risky_user_in_container = None
    
    service_account_info = jwt_body.get('kubernetes.io', {}).get('serviceaccount', {})
    if not service_account_info:
        return None
    
    # Check if the service account information is present in the first structure
    service_account_name = service_account_info.get('name')
    service_account_namespace = jwt_body.get('kubernetes.io', {}).get('namespace')

    if not service_account_name or not service_account_namespace:
        # Fallback to the alternative structure (kubernetes.io/serviceaccount/...)
        service_account_name = jwt_body.get('kubernetes.io/serviceaccount/service-account.name')
        service_account_namespace = jwt_body.get('kubernetes.io/serviceaccount/namespace')

    if service_account_name and service_account_namespace:
        for risky_user in risky_users:
            if risky_user.user_info.kind == 'ServiceAccount':
                if is_same_user(service_account_name,
                                service_account_namespace,
                                risky_user.user_info.name, 
                                risky_user.user_info.namespace):
                    risky_user_in_container = risky_user
                    break

    return risky_user_in_container



def get_risky_containers(pod, risky_users, read_token_from_container=False):
    risky_containers = []
    if read_token_from_container:
        # Skipping terminated and evicted pods
        # This will run only on the containers with the "ready" status
        if pod.status.container_statuses:
            for container in pod.status.container_statuses:
                if container.ready and container.state.running:
                    jwt_body, _ = get_jwt_token_from_container(pod, container.name)
                    if jwt_body:
                        risky_user = get_risky_user_from_container(jwt_body, risky_users)
                        if risky_user:
                           risky_containers.append(
                                Container(
                                    container.name, 
                                    risky_user.user_info.name,
                                    risky_user.user_info.namespace,  
                                    set() if risky_user is None else {risky_user}, 
                                    risky_user.priority
                                )
                            )

    else:
        # A dictionary for the volume
        volumes_dict = {}
        for volume in pod.spec.volumes or []:
            volumes_dict[volume.name] = volume
        for container in pod.spec.containers:
            risky_users_set = get_risky_users_from_container(container, risky_users, pod, volumes_dict)
            if not container_exists_in_risky_containers(risky_containers, container.name,
                                                        risky_users_set):
                if len(risky_users_set) > 0:
                    priority = get_highest_priority(risky_users_set)
                    risky_containers.append(
                        Container(container.name, None, pod.metadata.namespace, risky_users_set,
                                  priority))
    return risky_containers


# Get the highest priority user in the list
def get_highest_priority(risky_users_list):
    highest_priority = Priority.NONE
    for user in risky_users_list:
        if user.priority.value > highest_priority.value:
            highest_priority = user.priority
    return highest_priority


def get_risky_users_from_container(container, risky_users, pod, volumes_dict):
    risky_users_set = set()
    # '[]' for checking if 'container.volume_mounts' is None
    for volume_mount in container.volume_mounts or []:
        if volume_mount.name in volumes_dict:
            if volumes_dict[volume_mount.name].projected is not None:
                for source in volumes_dict[volume_mount.name].projected.sources or []:
                    if source.service_account_token is not None:
                        risky_user = is_user_risky(risky_users, pod.spec.service_account, pod.metadata.namespace)
                        if risky_user is not None:
                            risky_users_set.add(risky_user)
            elif volumes_dict[volume_mount.name].secret is not None:
                risky_user = get_jwt_and_decode(pod, risky_users, volumes_dict[volume_mount.name])
                if risky_user is not None:
                    risky_users_set.add(risky_user)
    return risky_users_set



def container_exists_in_risky_containers(risky_containers, container_name, risky_users_list):
    for risky_container in risky_containers:
        if risky_container.name == container_name:
            for user_name in risky_users_list:
                risky_container.service_account_name.append(user_name)
            return True
    return False


def default_path_exists(volume_mounts):
    for volume_mount in volume_mounts:
        if volume_mount.mount_path == "/var/run/secrets/kubernetes.io/serviceaccount":
            return True
    return False


def is_user_risky(risky_users, service_account, namespace):
    for risky_user in risky_users:
        if risky_user.user_info.name == service_account and risky_user.user_info.namespace == namespace:
            return risky_user
    return None


def get_jwt_and_decode(pod, risky_users, volume):
    from engine.jwt_token import decode_base64_jwt_token
    try:
        secret = api_client.CoreV1Api.read_namespaced_secret(name=volume.secret.secret_name,
                                                             namespace=pod.metadata.namespace)
    except Exception:
        secret = None
    try:
        if secret is not None and secret.data is not None:
            if 'token' in secret.data:
                decoded_data = decode_base64_jwt_token(secret.data['token'])
                token_body = json.loads(decoded_data)
                if token_body:
                    risky_user = get_risky_user_from_container(token_body, risky_users)
                    return risky_user
        raise Exception()
    except Exception:
        if secret is not None:
            return get_risky_user_from_container_secret(secret, risky_users)

def get_risky_user_from_container_secret(secret, risky_users):
    if secret is not None:
        global list_of_service_accounts
        if not list_of_service_accounts:
            list_of_service_accounts = api_client.CoreV1Api.list_service_account_for_all_namespaces()
        for sa in list_of_service_accounts.items:
            for service_account_secret in sa.secrets or []:
                if secret.metadata.name == service_account_secret.name:
                    for risky_user in risky_users:
                        if risky_user.user_info.name == sa.metadata.name:
                            return risky_user

def get_risky_pods(namespace=None, deep_analysis=False):
    risky_pods = []
    pods = list_pods_for_all_namespaces_or_one_namspace(namespace)
    risky_users = get_all_risky_subjects()
    for pod in pods.items:
        risky_containers = get_risky_containers(pod, risky_users, deep_analysis)
        if len(risky_containers) > 0:
            risky_pods.append(Pod(pod.metadata.name, pod.metadata.namespace, risky_containers))

    return risky_pods


# endregion- Risky Pods

def get_rolebindings_all_namespaces_and_clusterrolebindings():
    namespaced_rolebindings = Config.api_client.list_role_binding_for_all_namespaces()

    # TODO: check when this bug will be fixed
    # cluster_rolebindings = api_client.RbacAuthorizationV1Api.list_cluster_role_binding()
    # cluster_rolebindings = api_client.api_temp.list_cluster_role_binding()
    cluster_rolebindings = Config.api_client.list_cluster_role_binding()
    return namespaced_rolebindings, cluster_rolebindings


def get_rolebindings_and_clusterrolebindings_associated_to_subject(subject_name, kind, namespace):
    rolebindings_all_namespaces, cluster_rolebindings = get_rolebindings_all_namespaces_and_clusterrolebindings()
    associated_rolebindings = []

    for rolebinding in rolebindings_all_namespaces.items:
        # In case 'rolebinding.subjects' is 'None', 'or []' will prevent an exception.
        for subject in rolebinding.subjects or []:
            if subject.name.lower() == subject_name.lower() and subject.kind.lower() == kind.lower():
                if kind == SERVICEACCOUNT_KIND:
                    if subject.namespace.lower() == namespace.lower():
                        associated_rolebindings.append(rolebinding)
                else:
                    associated_rolebindings.append(rolebinding)

    associated_clusterrolebindings = []
    for clusterrolebinding in cluster_rolebindings:

        # In case 'clusterrolebinding.subjects' is 'None', 'or []' will prevent an exception.
        for subject in clusterrolebinding.subjects or []:
            if subject.name.lower() == subject_name.lower() and subject.kind.lower() == kind.lower():
                if kind == SERVICEACCOUNT_KIND:
                    if subject.namespace.lower() == namespace.lower():
                        associated_clusterrolebindings.append(clusterrolebinding)
                else:
                    associated_clusterrolebindings.append(clusterrolebinding)

    return associated_rolebindings, associated_clusterrolebindings


# Role can be only inside RoleBinding
def get_rolebindings_associated_to_role(role_name, namespace):
    rolebindings_all_namespaces = Config.api_client.list_role_binding_for_all_namespaces()
    associated_rolebindings = []

    for rolebinding in rolebindings_all_namespaces.items:
        if rolebinding.role_ref.name.lower() == role_name.lower() and rolebinding.role_ref.kind == ROLE_KIND and rolebinding.metadata.namespace.lower() == namespace.lower():
            associated_rolebindings.append(rolebinding)

    return associated_rolebindings


def get_rolebindings_and_clusterrolebindings_associated_to_clusterrole(role_name):
    rolebindings_all_namespaces, cluster_rolebindings = get_rolebindings_all_namespaces_and_clusterrolebindings()

    associated_rolebindings = []

    for rolebinding in rolebindings_all_namespaces.items:
        if rolebinding.role_ref.name.lower() == role_name.lower() and rolebinding.role_ref.kind == CLUSTER_ROLE_KIND:
            associated_rolebindings.append(rolebinding)

    associated_clusterrolebindings = []

    # for clusterrolebinding in cluster_rolebindings.items:
    for clusterrolebinding in cluster_rolebindings:
        if clusterrolebinding.role_ref.name.lower() == role_name.lower() and clusterrolebinding.role_ref.kind == CLUSTER_ROLE_KIND:
            associated_rolebindings.append(clusterrolebinding)

    return associated_rolebindings, associated_clusterrolebindings


def dump_containers_tokens_by_pod(pod_name, namespace, read_token_from_container=False):
    containers_with_tokens = []
    try:
        pod = api_client.CoreV1Api.read_namespaced_pod(name=pod_name, namespace=namespace)
    except ApiException:
        print(pod_name + " was not found in " + namespace + " namespace")
        return None
    if read_token_from_container:
        if pod.status.container_statuses:
            for container in pod.status.container_statuses:
                if container.ready:
                    jwt_body, raw_jwt_token = get_jwt_token_from_container(pod, container.name)
                    if jwt_body:
                        containers_with_tokens.append(
                            Container(container.name, token=jwt_body, raw_jwt_token=raw_jwt_token))

    else:
        fill_container_with_tokens_list(containers_with_tokens, pod)
    return containers_with_tokens


def fill_container_with_tokens_list(containers_with_tokens, pod):
    from engine.jwt_token import decode_base64_jwt_token
    for container in pod.spec.containers:
        for volume_mount in container.volume_mounts or []:
            for volume in pod.spec.volumes or []:
                if volume.name == volume_mount.name and volume.secret:
                    try:
                        secret = api_client.CoreV1Api.read_namespaced_secret(volume.secret.secret_name,
                                                                             pod.metadata.namespace)
                        if secret and secret.data and secret.data['token']:
                            decoded_data = decode_base64_jwt_token(secret.data['token'])
                            token_body = json.loads(decoded_data)
                            containers_with_tokens.append(Container(container.name, token=token_body,
                                                                    raw_jwt_token=None))
                    except ApiException:
                        print("No secret found.")


def dump_all_pods_tokens_or_by_namespace(namespace=None, read_token_from_container=False):
    pods_with_tokens = []
    pods = list_pods_for_all_namespaces_or_one_namspace(namespace)
    for pod in pods.items:
        containers = dump_containers_tokens_by_pod(pod.metadata.name, pod.metadata.namespace, read_token_from_container)
        if containers is not None:
            pods_with_tokens.append(Pod(pod.metadata.name, pod.metadata.namespace, containers))

    return pods_with_tokens


def dump_pod_tokens(name, namespace, read_token_from_container=False):
    pod_with_tokens = []
    containers = dump_containers_tokens_by_pod(name, namespace, read_token_from_container)
    pod_with_tokens.append(Pod(name, namespace, containers))

    return pod_with_tokens


def search_subject_in_subjects_by_kind(subjects, kind):
    subjects_found = []
    for subject in subjects:
        if subject.kind.lower() == kind.lower():
            subjects_found.append(subject)
    return subjects_found


# It get subjects by kind for all rolebindings.
def get_subjects_by_kind(kind):
    subjects_found = []
    rolebindings = Config.api_client.list_role_binding_for_all_namespaces()
    clusterrolebindings = Config.api_client.list_cluster_role_binding()
    for rolebinding in rolebindings.items:
        if rolebinding.subjects is not None:
            subjects_found += search_subject_in_subjects_by_kind(rolebinding.subjects, kind)

    for clusterrolebinding in clusterrolebindings:
        if clusterrolebinding.subjects is not None:
            subjects_found += search_subject_in_subjects_by_kind(clusterrolebinding.subjects, kind)

    return remove_duplicated_subjects(subjects_found)


def remove_duplicated_subjects(subjects):
    seen_subjects = set()
    new_subjects = []
    for s1 in subjects:
        if s1.namespace == None:
            s1_unique_name = ''.join([s1.name, s1.kind])
        else:
            s1_unique_name = ''.join([s1.name, s1.namespace, s1.kind])
        if s1_unique_name not in seen_subjects:
            new_subjects.append(s1)
            seen_subjects.add(s1_unique_name)

    return new_subjects


def get_rolebinding_role(rolebinding_name, namespace):
    rolebinding = None
    role = None
    try:
        rolebinding = Config.api_client.read_namespaced_role_binding(rolebinding_name, namespace)
        if rolebinding.role_ref.kind == ROLE_KIND:
            role = Config.api_client.read_namespaced_role(rolebinding.role_ref.name,
                                                                          rolebinding.metadata.namespace)
        else:
            role = Config.api_client.read_cluster_role(rolebinding.role_ref.name)

        return role
    except ApiException:
        if rolebinding is None:
            print("Could not find " + rolebinding_name + " rolebinding in " + namespace + " namespace")
        elif role is None:
            print(
                "Could not find " + rolebinding.role_ref.name + " role in " + rolebinding.role_ref.name + " rolebinding")
        return None


def get_clusterrolebinding_role(cluster_rolebinding_name):
    cluster_role = ''
    try:
        cluster_rolebinding = api_client.RbacAuthorizationV1Api.read_cluster_role_binding(cluster_rolebinding_name)
        cluster_role = api_client.RbacAuthorizationV1Api.read_cluster_role(cluster_rolebinding.role_ref.name)
    except ApiException as e:
        print(e)
        exit()

    return cluster_role


def get_roles_associated_to_subject(subject_name, kind, namespace):
    associated_rolebindings, associated_clusterrolebindings = get_rolebindings_and_clusterrolebindings_associated_to_subject(
        subject_name, kind, namespace)

    associated_roles = []
    for rolebind in associated_rolebindings:
        try:
            role = get_rolebinding_role(rolebind.metadata.name, rolebind.metadata.namespace)
            associated_roles.append(role)
        except ApiException as e:
            # 404 not found
            continue

    for clusterrolebinding in associated_clusterrolebindings:
        role = get_clusterrolebinding_role(clusterrolebinding.metadata.name)
        associated_roles.append(role)

    return associated_roles


def list_pods_for_all_namespaces_or_one_namspace(namespace=None):
    try:
        if namespace is None:
            pods = Config.api_client.list_pod_for_all_namespaces(watch=False)
        else:
            pods = Config.api_client.list_namespaced_pod(namespace)
        return pods
    except ApiException:
        return None


# https://<master_ip>:<port>/api/v1/namespaces/kube-system/secrets?fieldSelector=type=bootstrap.kubernetes.io/token
def list_boostrap_tokens_decoded():
    tokens = []
    secrets = api_client.CoreV1Api.list_namespaced_secret(namespace='kube-system',
                                                          field_selector='type=bootstrap.kubernetes.io/token')
    import base64

    for secret in secrets.items:
        tokens.append('.'.join((base64.b64decode(secret.data['token-id']).decode('utf-8'),
                                base64.b64decode(secret.data['token-secret']).decode('utf-8'))))

    return tokens
