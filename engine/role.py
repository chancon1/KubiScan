from kubernetes import client, config

# This class is also for ClusterRole
class Role:
    def __init__(self, name, priority, rules=None, namespace=None, kind=None, time=None,
                 findings=None, bound_service_accounts=None):
        self.name = name
        self.priority = priority
        self.rules = rules
        self.namespace = namespace
        self.kind = kind
        self.time = time
        self.findings = findings or []
        self.bound_service_accounts = bound_service_accounts or []

    @property
    def trigger_reasons(self):
        """One block per matched pattern: its name, score arithmetic and rules."""
        return [finding.render() for finding in self.findings]

    def get_rules(self):
        config.load_kube_config()
        v1 = client.RbacAuthorizationV1Api()
        if self.kind.lower() == "role":
            return (v1.read_namespaced_role(self.name, self.namespace)).rules
        else: # "clusterrole"
            return (v1.read_cluster_role(self.name)).rules