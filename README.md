[![GitHub release][release-img]][release]
[![License][license-img]][license]
![Stars](https://img.shields.io/github/stars/cyberark/KubiScan)

<img src="https://github.com/cyberark/KubiScan/blob/assets/kubiscan_logo.png" width="260">  
A tool for scanning Kubernetes cluster for risky permissions in Kubernetes's Role-based access control (RBAC) authorization model.   
The tool was published as part of the "Securing Kubernetes Clusters by Eliminating Risky Permissions" research https://www.cyberark.com/threat-research-blog/securing-kubernetes-clusters-by-eliminating-risky-permissions/.

---

## Table of Contents
- [Overview](#overview)
- [What can it do?](#what-can-it-do)
- [Usage](#usage)
  - [Container](#container)
  - [Directly with Python3](#directly-with-python3)
    - [Prerequisites](#prerequisites)
    - [Example for installation on Ubuntu](#example-for-installation-on-ubuntu)
    - [With KubeConfig file](#with-kubeconfig-file)
    - [From a remote with ServiceAccount token](#from-a-remote-with-serviceaccount-token)
  - [Scanning a static manifest dump](#scanning-a-static-manifest-dump)
- [Reading the report](#reading-the-report)
- [How a priority is decided](#how-a-priority-is-decided)
  - [The seven context modifiers](#the-seven-context-modifiers)
  - [Aggregation: always the maximum, never a sum](#aggregation-always-the-maximum-never-a-sum)
  - [Sensitive namespaces](#sensitive-namespaces)
- [Running as an in-cluster Job](#running-as-an-in-cluster-job)
- [Examples](#examples)
- [Demo](#demo)
- [Risky Roles YAML](#risky-roles-yaml)
- [Tests](#tests)
- [Showcase](#%EF%B8%8F-showcase)
- [License](#license)
- [References](#references)

---

## Overview
KubiScan helps cluster administrators identify permissions that attackers could potentially exploit to compromise the clusters.
This can be especially helpful on large environments where there are lots of permissions that can be challenging to track. 
KubiScan gathers information about risky roles\clusterroles, rolebindings\clusterrolebindings, users and pods, automating traditional manual processes and giving administrators the visibility they need to reduce risk.  

## What can it do? 
-	Score every finding by the context it was granted in, not by a constant attached to the permission - see [How a priority is decided](#how-a-priority-is-decided)
-	Identify risky Roles\ClusterRoles
-	Identify risky RoleBindings\ClusterRoleBindings
-	Identify risky Subjects (Users, Groups and ServiceAccounts)
-	Identify risky Pods\Containers
-	Dump tokens from pods (all or by namespace)
-	Get associated RoleBindings\ClusterRoleBindings to Role, ClusterRole or Subject (user, group or service account)
-	List Subjects with specific kind ('User', 'Group' or 'ServiceAccount')
-	List rules of RoleBinding or ClusterRoleBinding
-	Show Pods that have access to secret data through a volume or environment variables
- Get bootstrap tokens for the cluster
- CVE scan
- EKS\AKS\GKE support
- Scan an offline dump of manifests instead of a live cluster
- Run as an in-cluster Job and emit one JSON event per finding for log collectors

## Usage
### Container

You can run it like that:  
```
./docker_run.sh <kube_config_file>
# For example: ./docker_run.sh ~/.kube/config
```

It will copy all the files linked inside the config file into the container and spwan a shell into the container.

To build the Docker image run:  
```
docker build -t kubiscan .
```

### Directly with Python3
#### Prerequisites:
-	__Python 3.6+__
-	__Pip3__
-	[__Kubernetes Python Client__](https://github.com/kubernetes-client/python) 
-	[__Prettytable__](https://pypi.org/project/PTable)
-	__openssl__ (built-in in ubuntu) - used only for join token

#### Example for installation on Ubuntu:
```
apt-get update  
apt-get install -y python3 python3-pip 
pip3 install -r requirements.txt  
```

Run `alias kubiscan='python3 /<KubiScan_folder>/KubiScan.py'` to use `kubiscan`.  

After installing all of the above requirements you can run it in two different ways:  
#### With KubeConfig file:
Make sure you have access to `~/.kube/config` file and all the relevant certificates, simply run:  
`kubiscan <command>`  
For example: `kubiscan -rs` will show all the risky subjects (users, service accounts and groups).  

#### From a remote with ServiceAccount token
Some functionality requires a **privileged** service account with the following permissions:  
- **resources**: `["roles", "clusterroles", "rolebindings", "clusterrolebindings", "pods", "secrets"]`  
  **verbs**: `["get", "list"]`  
- **resources**: `["pods/exec"]`  
  **verbs**: `["create", "get"]`  

But most of the functionalities are not, so you can use this settings for limited service account:  
It can be created by running:
```
kubectl apply -f - << EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kubiscan-sa
  namespace: default
---
apiVersion: v1
kind: Secret
type: kubernetes.io/service-account-token
metadata:
  name: kubiscan-sa-secret
  annotations:
    kubernetes.io/service-account.name: kubiscan-sa
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata: 
  name: kubiscan-clusterrolebinding
subjects: 
- kind: ServiceAccount 
  name: kubiscan-sa
  namespace: default
  apiGroup: ""
roleRef: 
  kind: ClusterRole
  name: kubiscan-clusterrole
  apiGroup: ""
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata: 
  name: kubiscan-clusterrole
rules: 
- apiGroups: ["*"]
  resources: ["roles", "clusterroles", "rolebindings", "clusterrolebindings", "pods"]
  verbs: ["get", "list"]
EOF
```

Note that from Kubernetes 1.24, the creation of service account doesn't create a secret. This means that we need to create the secret.  
Before 1.24, you can remove the `Secret` object from the above commands and save the service account's token to a file:  
`kubectl get secrets $(kubectl get sa kubiscan-sa -o=jsonpath='{.secrets[0].name}') -o=jsonpath='{.data.token}' | base64 -d > token`

From 1.24, you don't need to change anything and save the token like that:  
```
kubectl get secrets kubiscan-sa-secret -o=jsonpath='{.data.token}' | base64 -d > token  
```

After saving the token into the file, you can use it like that:  
`python3 ./KubiScan.py -ho <master_ip:master_port> -t /token <command>`  

For example:   
```
alias kubiscan='python3 /<KubiScan_folder>/KubiScan.py
kubiscan -ho 192.168.21.129:8443 -t /token -rs
```

Notice that you can also use the certificate authority (ca.crt) to verify the SSL connection:    
```
kubiscan -ho <master_ip:master_port> -t /token -c /ca.crt <command>
```

To remove the privileged service account, run the following commands: 
```
kubectl delete clusterroles kubiscan-clusterrole  
kubectl delete clusterrolebindings kubiscan-clusterrolebinding   
kubectl delete sa kubiscan-sa  
kubectl delete secrets kubiscan-sa-secret
```

### Scanning a static manifest dump
Instead of talking to a cluster, KubiScan can read a file containing the manifests to
analyse. Pass it with `-f`\\`--file` and every other switch keeps working:

```
kubiscan -f combined.json -rar -r
kubiscan -f combined.yaml -rs
```

Both `.json` and `.yaml` are accepted. The file holds objects under `items`, the same
shape `kubectl get ... -o json` produces, and may contain Roles, ClusterRoles,
RoleBindings, ClusterRoleBindings and Pods together.

## Reading the report

Reports for Roles\ClusterRoles carry three columns worth explaining.

**Rules** lists every rule of the role, prefixed with the apiGroup it belongs to:

```
[core]                     (get,list,delete)->(secrets)
[apps]                     (get,list,watch)->(deployments)
[rbac.authorization.k8s.io] (create,bind,escalate)->(clusterroles)
```

`[core]` is the empty apiGroup `""` - the original Kubernetes API served under `/api/v1`
(pods, services, secrets, configmaps, namespaces, serviceaccounts and their subresources).
Everything else is served under `/apis/<group>/<version>`. The group matters because the
same resource name can exist in several groups: `[core] secrets` are Kubernetes Secrets,
while `[vault.example.com] secrets` is an unrelated custom resource that merely shares
the name.

**Triggered By** carries one line per matched pattern: what fired, what it scored, and
what made it that severe.

```
risky-secrets-read: HIGH -> CRITICAL (clusterWide, boundToEveryone: system:authenticated)
risky-configmaps-read: MEDIUM -> HIGH (clusterWide)
risky-events-write: LOW -> MEDIUM (clusterWide)
```

Read a line as three parts:

- **the pattern** from `risky_roles.yaml` that matched - `risky-secrets-read`;
- **the score** - `HIGH -> CRITICAL` means the permission is worth HIGH on its own and the
  context pushed it to CRITICAL. A single level (`CRITICAL`) means nothing moved it;
- **the reasons in brackets** - the context modifiers that fired, with the detail that is
  not already obvious from their name. Nothing in brackets means the pattern scored at its
  base.

The number of lines is not a severity: six lines are six distinct permissions, not
something six times worse. The role's own `Priority` is the highest line, never a sum -
see [How a priority is decided](#how-a-priority-is-decided).

Pass `--explain` to expand every line into the full block - the rules that matched, and
one line per modifier with its delta and a sentence of reasoning:

```
risky-secrets-read  HIGH -> CRITICAL
  [core] secrets: get,list
  +1 clusterWide (cluster-wide via ClusterRoleBinding: too-open)
  +1 boundToEveryone (granted to system:authenticated)
```

**Bound Service Accounts** lists the subjects the role is granted to. Users and Groups are
included alongside service accounts, since a risky role bound to a group such as
`system:authenticated` is the most severe finding there is:

```
sa-app@prod [SA NS] (via ClusterRoleBinding: app-admin [ClusterRoleBinding name])
system:authenticated [Group] (via ClusterRoleBinding: too-open [ClusterRoleBinding name])
```

### Built-in system roles
Roles whose name starts with `system:` are excluded from the Role\ClusterRole reports
(`-rr`, `-rcr`, `-rar`) by default - they are shipped by Kubernetes and dominate the
output. Add `--include-system` to see them. The filter does not currently apply to the
binding, subject or pod reports, and is ignored by `-a`.

## How a priority is decided

A permission is not dangerous in the abstract. "Read secrets" granted to one service
account in one team namespace is a fact of life; the same rule on a ClusterRole bound to
`system:authenticated` means every user of the cluster reads every secret. KubiScan scores
the second one higher than the first, and says why.

Each pattern in `risky_roles.yaml` declares a **base priority**: what the permission is
worth in the plain case - a namespaced Role, bound, in an unremarkable namespace. Seven
**context modifiers** then move it, each by one level, and the result is clamped to
LOW..CRITICAL.

```
finding = base priority  +/-  the modifiers that apply   (clamped to LOW..CRITICAL)
```

A finding never decays to nothing. Context can say "not urgent", but the permission is
still there and still appears in the report - at LOW if everything argued against it.

### The seven context modifiers

| Modifier | Fires when | Effect |
|---|---|---|
| `clusterWide` | A ClusterRoleBinding grants the ClusterRole, so the permission covers every namespace | +1 |
| `namespacedBindingOnly` | Only RoleBindings reference the ClusterRole. Binding a ClusterRole with a RoleBinding grants its namespaced rules inside that one namespace, so its **cluster-scoped** rules never take effect | -1 |
| `sensitiveNamespace` | The grant lands in a namespace listed in `sensitive_namespaces.yaml`. Not applied on top of `clusterWide`, which already covers every namespace there is | +1 |
| `boundToEveryone` | A binding hands the role to `system:authenticated` or `system:unauthenticated` | +1 |
| `privilegedSaReachable` | The permission can run a workload in a namespace that hosts an already-critical service account. Creating a Pod lets you name any service account of that namespace as its identity | +1 |
| `resourceNamesRestricted` | Every matched rule is pinned to named objects, on verbs RBAC actually narrows by name. `create`, `list`, `watch` and `deletecollection` are never narrowed, so mixing one of those in earns no discount | -1 |
| `unbound` | No RoleBinding or ClusterRoleBinding references the role. A latent risk, not an active one | -1 |

Not every pattern carries all seven. The set is chosen by the pattern's `profile`: recon
permissions such as "list pods" only ever carry `unbound`, because almost every
authenticated user already holds them through the built-in `system:basic-user`, and
`clusterWide` would fire on every cluster in existence.

`privilegedSaReachable` is the one modifier that depends on the scan's own result, so the
scan runs in two passes: the first scores everything else, the map of already-critical
service accounts is built from that result, and the second pass settles the findings that
depend on it. The map is never consulted while it is being built.

### Aggregation: always the maximum, never a sum

Adding is confined to a single finding. Everywhere above it, the answer is the worst case:

```
finding        = base +/- its own modifiers        <- the only place anything is added
role           = max(its findings)
binding        = max(the role's findings, rescored for that one binding)
subject        = max(the bindings it appears in)   (ServiceAccount, User, Group)
container/pod  = max(the subjects whose token it mounts)
```

A role with three MEDIUM findings stays MEDIUM. The priority answers "how bad is the worst
thing this grants", not "how many remarks does it have" - otherwise twenty harmless LOW
permissions would outrank a single cluster-wide secret read.

The binding line matters in practice. A ClusterRole reached by ten RoleBindings and one
ClusterRoleBinding is CRITICAL as a role, but in the binding report (`-rb`, `-rcb`, `-rab`)
the ten RoleBindings stay HIGH and the single ClusterRoleBinding is the CRITICAL one - so
the report names the binding that has to be fixed.

### Sensitive namespaces

`sensitive_namespaces.yaml` ships the list that `sensitiveNamespace` uses: the Kubernetes
control plane (`kube-system`, `kube-public`, `kube-node-lease`) plus common policy,
ingress and infrastructure namespaces. Tune it to the cluster:

```
kubiscan -rar --sensitive-namespaces-add prod,payments      # extend the shipped list
kubiscan -rar --sensitive-namespaces prod,payments          # replace it entirely
```

The namespace that counts is the one where the grant **applies**: a Role's own namespace
when something is bound to it, and the namespace of each RoleBinding for a ClusterRole. An
unbound role has no place of effect and earns no namespace bump - `unbound` applies
instead.

## Running as an in-cluster Job

`deploy/kubiscan.yaml` runs a one-off scan from inside the cluster. It creates the
`kubiscan` namespace, a service account with read-only RBAC permissions, and a Job:

```
kubectl apply -f deploy/kubiscan.yaml
kubectl -n kubiscan wait --for=condition=complete job/kubiscan-scan --timeout=300s
kubectl -n kubiscan logs job/kubiscan-scan
```

The container entry point (`entrypoint.sh`) builds a kubeconfig from the pod's service
account token, runs `KubiScan.py -rar -r -j /tmp/report.json`, and prints **one JSON object
per finding** on stdout so a log collector can pick them up line by line:

```json
{
  "scan_timestamp": "2026-08-04T19:51:00Z",
  "scan_tool": "kubiscan",
  "section": "Risky Roles and ClusterRoles",
  "Priority": "CRITICAL",
  "Kind": "ClusterRole",
  "Namespace": null,
  "Name": "mock-secrets-reader-everyone",
  "Creation Time": "Tue Aug  4 19:47:06 2026 (0 days)",
  "Rules": "[core] (get,list)->(secrets)",
  "Triggered By": "risky-secrets-read: HIGH -> CRITICAL (clusterWide, boundToEveryone: system:authenticated)",
  "Bound Service Accounts": "system:authenticated [Group] (via ClusterRoleBinding: mock-secrets-reader-everyone [ClusterRoleBinding name])"
}
```

`Rules`, `Triggered By` and `Bound Service Accounts` hold one entry per line, as `\n`
inside the JSON string - the event itself is always a single line, so a log collector
never has to stitch one back together.

Each event carries the scan timestamp, the report section it came from, and the report
columns as-is. The Job is annotated for Splunk (`splunk.com/index`,
`splunk.com/sourcetype`); adjust or drop those annotations to suit your collector.

The findings themselves carry no cluster identifier - a Kubernetes cluster has no canonical
name, and the value is best added by the log collector, which already knows which cluster
it runs in.

To scan on a schedule, wrap the Job in a CronJob or let your GitOps tooling re-apply it.

## Examples  
To see all the examples, run `python3 KubiScan.py -e` or from within the container `kubiscan -e`.  

## Demo  
A small example of KubiScan usage: 
<p><a href="https://cyberark.wistia.com/medias/0lt642okgn?wvideo=0lt642okgn"><img src="https://github.com/cyberark/KubiScan/blob/assets/kubiscan_embeded.png?raw=true" width="600"></a></p>

## Risky Roles YAML
`risky_roles.yaml` holds the matrix: 170 patterns across 10 categories, each a template of
rules that is compared against every Role and ClusterRole in the cluster. A role matching a
pattern's rules is reported. Each of us defines "risky" differently, so the file is meant
to be edited - add, remove or re-rank patterns to match your policy.

A pattern is described by:

| Field | Meaning |
|---|---|
| `name` | identifier shown in the report |
| `priority` | **base** score - what the permission is worth in the plain namespaced case, before context |
| `scope` | `namespaced` (default) or `cluster`, see below |
| `appliesTo` | `[Role, ClusterRole]` unless narrowed; usually left implicit, `scope` covers it |
| `profile` | named set of context modifiers from the `profiles:` block at the top of the file |
| `modifiers` | inline overrides merged on top of the profile |
| `category` | grouping, e.g. `privilege-escalation`, `credential-access`, `recon` |
| `matchesAnyApiGroup` | "total control of whichever group this is", as opposed to `apiGroups: ["*"]` |

### How a pattern is matched

Matching is context-free: the same role yields the same findings however it is bound.
Turning those findings into severities is the [scoring model's](#how-a-priority-is-decided)
job, and it needs the whole cluster to do it.

A role matches a pattern when everything lines up:

- **scope** - a pattern marked `scope: cluster` names a resource that lives outside any
  namespace (`nodes`, `clusterroles`, `persistentvolumes`). A namespaced Role can never
  grant it, so such patterns are not even evaluated against one. A Role with
  `get nodes/proxy` grants nothing and is not reported.
- **rules of a pattern are AND-ed** - a pattern holding two rules matches only when both
  are satisfied, possibly by two different rules of the role. That is what makes the
  escalation-chain patterns work: half a chain is not a chain.
- **resources inside one rule are also AND-ed** - a rule listing
  `["certificates", "certificaterequests"]` only matches a role holding both. Write one
  pattern per resource unless you really mean the conjunction.
- **verbs are OR-ed** - holding **any one** of the listed verbs is enough, so
  `risky-secrets-read` fires on a plain `get`.
- **apiGroups must name the group the resource really lives in** - `""` for the core
  group. `[core] secrets` is a Kubernetes Secret; `[vault.example.com] secrets` is an
  unrelated custom resource that merely shares the name, and it does not match the
  Kubernetes-native pattern.

Two spellings of a wildcard mean different things, and the difference is deliberate:

| In a pattern | Means | Satisfied by |
|---|---|---|
| `apiGroups: ["*"]` | group-unrestricted access | only a rule that also says `"*"` |
| `matchesAnyApiGroup: true` | total control of whichever single group this is | `apiGroups: [x], resources: ["*"]` for any `x` |

Without that split the wildcard patterns swallowed real findings such as
`apiGroups: [constraints.gatekeeper.sh], resources: ["*"]`. A pattern verb of `"*"` works
the same way: it asks for unrestricted verb access, and only a rule that also says `"*"`
provides it.

One role can match several patterns and is then reported with several lines under
`Triggered By`. The exception is a role holding a full wildcard (`*`/`*`/`*`): it subsumes
everything more specific, so it collapses into a single finding instead of the whole
matrix.

## Tests

```bash
python tests/run_all.py
```

No cluster needed - the guards run against `risky_roles.yaml` and the scoring engine
directly. `tests/fixtures/detected_permissions.txt` baselines every permission the matrix
can detect, so a verb quietly disappearing from a pattern shows up in review as a deleted
line rather than as silence. See `tests/README.md` for what each check is for and which
traps this codebase has already fallen into.

## ❤️ Showcase  
* Presented at RSA 2020 ["Compromising Kubernetes Cluster by Exploiting RBAC Permissions"](https://www.youtube.com/watch?v=1LMo0CftVC4)
* Presented at RSA 2022 ["Attacking and Defending Kubernetes Cluster: Kubesploit vs KubiScan"](https://www.youtube.com/watch?v=xRqYSDKi6a0)
* Article by PortSwigger ["KubiScan: Open source Kubernetes security tool showcased at Black Hat 2020"](https://portswigger.net/daily-swig/kubiscan-open-source-kubernetes-security-tool-showcased-at-black-hat-2020)


## License
Copyright (c) 2020 CyberArk Software Ltd. All rights reserved  
This repository is licensed under GPL-3.0 License - see [`LICENSE`](LICENSE) for more details.

## References:
For more comments, suggestions or questions, you can contact Eviatar Gerzi ([@g3rzi](https://twitter.com/g3rzi)) and CyberArk Labs.

[release-img]: https://img.shields.io/github/release/cyberark/kubiscan.svg
[release]: https://github.com/cyberark/kubiscan/releases

[license-img]: https://img.shields.io/github/license/cyberark/kubiscan.svg
[license]: https://github.com/cyberark/kubiscan/blob/master/LICENSE
