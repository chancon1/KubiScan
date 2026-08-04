# This class is also for ClusterRoleBinding
class RoleBinding:
    def __init__(self, name, priority, namespace=None, kind=None, subjects=None, time=None,
                 role_ref=None, findings=None):
        self.name = name
        self.priority = priority
        self.namespace = namespace
        self.kind = kind
        self.subjects = subjects
        self.time = time
        # Which role this binding grants; needed to report a subject's real rules.
        self.role_ref = role_ref
        # The role's findings, rescored for this binding alone. A ClusterRole is
        # critical behind a ClusterRoleBinding and often inert behind a
        # namespaced RoleBinding, so the binding's own arithmetic is what
        # explains its priority.
        self.findings = findings or []

    @property
    def trigger_reasons(self):
        """One block per matched pattern: its name, score arithmetic and rules."""
        return [finding.render() for finding in self.findings]