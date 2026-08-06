"""Escalation chains a subject assembles out of several roles.

Two ways to get this wrong, and the second is worse than the first. Missing a
chain leaves the report saying a cluster is fine when a service account can take
it over. Inventing one - by joining permissions that never meet, in different
namespaces or on different subjects - fills the top of the report with grants
nobody holds, which is how a reader learns to stop reading it.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.priority import Priority  # noqa: E402
from engine.scan_context import BoundBinding, RoleFacts, ScanContext  # noqa: E402
from engine.subject_chain import build_subject_chains  # noqa: E402
from misc.constants import (CLUSTER_ROLE_BINDING_KIND, CLUSTER_ROLE_KIND,  # noqa: E402
                            ROLE_BINDING_KIND, ROLE_KIND)
from tests.helpers import Subject, rule  # noqa: E402

PODS_CREATE = [rule([''], ['pods'], ['create'])]
SECRETS_READ = [rule([''], ['secrets'], ['get', 'list'])]
BOTH_LEGS = PODS_CREATE + SECRETS_READ

APP = Subject('ServiceAccount', 'app', 'team-a')
OTHER = Subject('ServiceAccount', 'other', 'team-a')


def role_key(name, namespace):
    return (ROLE_KIND, name, namespace)


def cluster_key(name):
    return (CLUSTER_ROLE_KIND, name, None)


def chain_context(roles, index):
    """A context holding these role rules and this binding index."""
    ctx = ScanContext([], [], sensitive_namespaces=set(['kube-system']))
    ctx._index = dict(index)
    ctx._roles_by_key = {key: RoleFacts(rules) for key, rules in roles.items()}
    ctx.privileged_sa_known = True
    return ctx


def rb(name, namespace, subjects):
    return BoundBinding(ROLE_BINDING_KIND, name, namespace, subjects)


def crb(name, subjects):
    return BoundBinding(CLUSTER_ROLE_BINDING_KIND, name, None, subjects)


def names(chains):
    return sorted(chain.finding.pattern_name for chain in chains)


def test_chain_split_across_two_roles_is_found(report):
    """The whole point: two dull roles, one subject, one escalation path."""
    ctx = chain_context(
        {role_key('pods', 'team-a'): PODS_CREATE,
         role_key('secrets', 'team-a'): SECRETS_READ},
        {role_key('pods', 'team-a'): [rb('rb-pods', 'team-a', [APP])],
         role_key('secrets', 'team-a'): [rb('rb-secrets', 'team-a', [APP])]})
    chains = build_subject_chains(ctx)

    report('a chain split across two roles is found',
           names(chains) == ['risky-chain-pod-and-secrets'],
           'got {0}'.format(names(chains)))
    if not chains:
        return
    chain = chains[0]
    report('the chain is scored at the pattern base priority',
           chain.finding.priority == Priority.CRITICAL,
           'got {0}'.format(chain.finding.priority.name))
    report('the chain names both contributing roles',
           sorted(grant.role_name for grant in chain.grants) == ['pods', 'secrets'],
           'got {0}'.format([grant.role_name for grant in chain.grants]))
    report('each leg names the role that supplied it',
           [sorted(g.role_name for g in suppliers) for _, suppliers in chain.legs]
           == [['pods'], ['secrets']],
           'got {0}'.format([[g.role_name for g in s] for _, s in chain.legs]))


def test_legs_in_different_namespaces_do_not_combine(report):
    """Creating a pod in one namespace reaches no secret in another."""
    ctx = chain_context(
        {role_key('pods', 'team-a'): PODS_CREATE,
         role_key('secrets', 'team-b'): SECRETS_READ},
        {role_key('pods', 'team-a'): [rb('rb-pods', 'team-a', [APP])],
         role_key('secrets', 'team-b'): [rb('rb-secrets', 'team-b', [APP])]})
    report('legs in different namespaces do not combine',
           build_subject_chains(ctx) == [],
           'got {0}'.format(names(build_subject_chains(ctx))))


def test_legs_of_different_subjects_do_not_combine(report):
    """Two subjects sharing a binding do not pool their permissions."""
    ctx = chain_context(
        {role_key('pods', 'team-a'): PODS_CREATE,
         role_key('secrets', 'team-a'): SECRETS_READ},
        {role_key('pods', 'team-a'): [rb('rb-pods', 'team-a', [APP])],
         role_key('secrets', 'team-a'): [rb('rb-secrets', 'team-a', [OTHER])]})
    report('legs held by different subjects do not combine',
           build_subject_chains(ctx) == [],
           'got {0}'.format(names(build_subject_chains(ctx))))


def test_single_role_chain_is_left_to_the_role_report(report):
    """One role granting the whole chain is already reported against that role."""
    ctx = chain_context(
        {role_key('both', 'team-a'): BOTH_LEGS,
         role_key('secrets', 'team-a'): SECRETS_READ},
        {role_key('both', 'team-a'): [rb('rb-both', 'team-a', [APP])],
         role_key('secrets', 'team-a'): [rb('rb-secrets', 'team-a', [APP])]})
    report('a chain one role already grants is not repeated',
           build_subject_chains(ctx) == [],
           'got {0}'.format(names(build_subject_chains(ctx))))


def test_cluster_wide_legs_reach_every_namespace(report):
    """Two ClusterRoleBindings put the chain everywhere, and say so once."""
    ctx = chain_context(
        {cluster_key('pods'): PODS_CREATE, cluster_key('secrets'): SECRETS_READ},
        {cluster_key('pods'): [crb('crb-pods', [APP])],
         cluster_key('secrets'): [crb('crb-secrets', [APP])]})
    chains = build_subject_chains(ctx)
    report('a chain built from ClusterRoleBindings is cluster-wide',
           len(chains) == 1 and chains[0].is_cluster_wide,
           'got {0}'.format([(c.finding.pattern_name, c.is_cluster_wide) for c in chains]))


def test_mixed_reach_is_confined_to_the_namespaced_leg(report):
    """A cluster-wide leg plus a namespaced one is a chain in that namespace only.

    The tempting answer is 'cluster-wide', because one of the two grants is. It
    would be wrong: the chain only closes where both legs land.
    """
    ctx = chain_context(
        {cluster_key('secrets'): SECRETS_READ, role_key('pods', 'team-a'): PODS_CREATE},
        {cluster_key('secrets'): [crb('crb-secrets', [APP])],
         role_key('pods', 'team-a'): [rb('rb-pods', 'team-a', [APP])]})
    chains = build_subject_chains(ctx)
    report('a half cluster-wide chain is reported for one namespace',
           len(chains) == 1 and not chains[0].is_cluster_wide
           and chains[0].scope.namespace == 'team-a',
           'got {0}'.format([(c.is_cluster_wide, c.scope.namespace) for c in chains]))
    report('a namespaced chain does not claim cluster-wide reach',
           chains and 'clusterWide' not in [m.name for m in chains[0].finding.modifiers],
           'got {0}'.format(chains and [m.name for m in chains[0].finding.modifiers]))


def test_sensitive_namespace_still_applies(report):
    """Context scoring works on a chain exactly as it does on a role."""
    ctx = chain_context(
        {role_key('pods', 'kube-system'): PODS_CREATE,
         role_key('secrets', 'kube-system'): SECRETS_READ},
        {role_key('pods', 'kube-system'): [rb('rb-pods', 'kube-system', [APP])],
         role_key('secrets', 'kube-system'): [rb('rb-secrets', 'kube-system', [APP])]})
    chains = build_subject_chains(ctx)
    report('a chain in a sensitive namespace is scored for it',
           chains and 'sensitiveNamespace' in [m.name for m in chains[0].finding.modifiers],
           'got {0}'.format(chains and [m.name for m in chains[0].finding.modifiers]))


def test_subject_less_binding_grants_no_chain(report):
    """A binding with no subjects hands its role to nobody, here as everywhere."""
    ctx = chain_context(
        {role_key('pods', 'team-a'): PODS_CREATE,
         role_key('secrets', 'team-a'): SECRETS_READ},
        {role_key('pods', 'team-a'): [rb('rb-pods', 'team-a', [APP])],
         role_key('secrets', 'team-a'): [rb('rb-secrets', 'team-a', [])]})
    report('a subject-less binding contributes no leg',
           build_subject_chains(ctx) == [],
           'got {0}'.format(names(build_subject_chains(ctx))))


TESTS = [test_chain_split_across_two_roles_is_found,
         test_legs_in_different_namespaces_do_not_combine,
         test_legs_of_different_subjects_do_not_combine,
         test_single_role_chain_is_left_to_the_role_report,
         test_cluster_wide_legs_reach_every_namespace,
         test_mixed_reach_is_confined_to_the_namespaced_leg,
         test_sensitive_namespace_still_applies,
         test_subject_less_binding_grants_no_chain]
