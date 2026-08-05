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
  - [Binding-centred risk events](#binding-centred-risk-events)
- [How a priority is decided](#how-a-priority-is-decided)
  - [The seven context modifiers](#the-seven-context-modifiers)
  - [Aggregation: always the maximum, never a sum](#aggregation-always-the-maximum-never-a-sum)
  - [Sensitive namespaces](#sensitive-namespaces)
- [Running as an in-cluster Job](#running-as-an-in-cluster-job)
- [Live-cluster validation](#live-cluster-validation)
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
- Run as an in-cluster Job and emit one JSON event per risky pattern and concrete grant
  for log collectors

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
Kubernetes-provided `system:*` objects dominate an unfiltered report. By default the role
reports hide `system:*` roles, the binding reports hide `system:*` bindings, and the
subject report hides a subject whose risk comes only from `system:*` roles. A custom
binding to a built-in role remains visible in the binding report. Add `--include-system`
to restore these objects. Pod/container reporting is unchanged.

### Binding-centred risk events

`--risk-events` is the compact log-collector view. Instead of putting every finding and
every binding of a role into one large record, it emits one event for one risky pattern
through one concrete binding:

```
python3 KubiScan.py --risk-events
python3 KubiScan.py --risk-events -j report.json
```

A ClusterRole referenced by a namespaced RoleBinding and a ClusterRoleBinding therefore
becomes two events with different scopes and, when appropriate, different priorities.
Each event answers the questions needed for review without printing the whole role:

```json
{
  "Summary": "All authenticated users can read Kubernetes Secrets cluster-wide",
  "Priority": "CRITICAL",
  "Score": "HIGH -> CRITICAL",
  "Status": "ACTIVE",
  "Risk": "risky-secrets-read",
  "Granted To": ["Group system:authenticated"],
  "Permission": ["[core] secrets: get,list,watch"],
  "Role": "ClusterRole secret-reader",
  "Binding": "ClusterRoleBinding global-reader",
  "Scope": "cluster-wide",
  "Why": [
    "Reading Secrets exposes the credentials and sensitive data stored in them.",
    "Cluster-wide via ClusterRoleBinding: global-reader.",
    "Granted to system:authenticated."
  ]
}
```

`ACTIVE` means a binding currently grants the permission to at least one subject.
`LATENT` means either that the role is unbound or that the binding has no subjects. The
normal Role/ClusterRole and binding reports remain available and keep their old schema.

Schema v2 is deliberately pattern-granular: a role that matches 20 patterns through one
binding emits 20 events, and the Job emits the complete snapshot on every run. This gives
precise evidence but can create high event volume in operator-heavy clusters. The
[live-cluster validation](#live-cluster-validation) measured this effect. Grant-level
aggregation, ClusterRole `aggregationRule` resolution, separate impact/review priority,
and change-only emission are documented there as the next design iteration; they are not
implemented in schema v2.

System filtering is deliberately grant-aware in this view. Kubernetes' own `system:*`
role plus `system:*` binding pairs are hidden by default, but a custom binding to a
`system:*` role stays visible because it is a deliberate grant. `--include-system`
restores everything.

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
account token, runs the binding-centred `--risk-events` report, and prints **one JSON
object per event** on stdout so a log collector can pick them up line by line:

```json
{
  "scan_timestamp": "2026-08-04T19:51:00Z",
  "scan_tool": "kubiscan",
  "section": "RBAC Risk Events",
  "schema_version": 2,
  "event_type": "rbac_risk",
  "event_id": "18bd6f3c6930a8556ac7a2a6bc3c50b665e87d1c8cd91b3f1ec582df943880da",
  "Review Order": 1,
  "Summary": "All authenticated users can read Kubernetes Secrets cluster-wide",
  "Priority": "CRITICAL",
  "Score": "HIGH -> CRITICAL",
  "Status": "ACTIVE",
  "Risk": "risky-secrets-read",
  "Granted To": ["Group system:authenticated"],
  "Permission": ["[core] secrets: get,list,watch"],
  "Role": "ClusterRole mock-secrets-reader-everyone",
  "Binding": "ClusterRoleBinding too-open",
  "Scope": "cluster-wide",
  "Why": [
    "Reading Secrets exposes the credentials and sensitive data stored in them.",
    "Cluster-wide via ClusterRoleBinding: too-open.",
    "Granted to system:authenticated."
  ]
}
```

The multivalue fields (`Granted To`, `Permission`, `Why`) remain JSON arrays, so Splunk
can search an individual subject or permission without parsing display text. The event
itself is always one JSON line, so a collector never has to stitch one back together.

Each event carries the scan timestamp, the report section it came from, and the report
columns as-is. The Job is annotated for Splunk (`splunk.com/index`,
`splunk.com/sourcetype`); adjust or drop those annotations to suit your collector.

`event_id` is a stable SHA-256 fingerprint of pattern, role and binding. It stays the same
across scans so Splunk can track a grant whose priority changes. KubiScan deliberately does
not add a cluster field: Fluent Bit or the Splunk agent should attach that deployment
context. When correlating several clusters, use that external field together with
`event_id` as the unique key.

`Review Order` is calculated after sorting by priority, active/latent state, scope,
sensitive namespace and subject exposure. It is intended as the default order inside one
scan; `CRITICAL/ACTIVE` cluster-wide grants to broad groups come first.

The entrypoint defaults to the event schema. Set `KUBISCAN_REPORT_MODE=roles` to roll back
to the legacy role-centred JSON without changing the image.

To scan on a schedule, wrap the Job in a CronJob or let your GitOps tooling re-apply it.

## Live-cluster validation

The event pipeline was exercised end to end on Kubernetes v1.36.1 in Docker Desktop on
2026-08-06. The test installed Kyverno, ingress-nginx, cert-manager, an nginx workload,
and the Cilium operator/RBAC resources, then added deliberately risky mock accounts,
roles and bindings. The current branch was built as a local image and executed through
an in-cluster Job, not only through the host CLI.

The Job completed in six seconds and wrote 471 valid JSON lines. Every line parsed as a
schema-v2 `rbac_risk` event, all 471 IDs were non-empty and unique, and no event contained
a cluster-name field. The collector is expected to add cluster context externally.

| Result | Count |
|---|---:|
| `CRITICAL` | 104 |
| `HIGH` | 99 |
| `MEDIUM` | 98 |
| `LOW` | 170 |
| `ACTIVE` | 252 |
| `LATENT` | 219 |

The broad mock grant to `system:authenticated` sorted first, followed by other active
cluster-wide risks; the unbound mock Pod creator sorted as `MEDIUM/LATENT`. The nginx
deployment reached 1/1 ready and its test Ingress returned HTTP 200.

The run also exposed an important scale limit. Only 59 risky roles produced 471 events:
Kyverno accounted for 224 pattern events, while the built-in `admin` and `edit` roles
produced 64 and 49 latent events. Grouping the exact same result by resolved
`Role + Binding` would produce 62 grant records, of which 40 are active and have at least
one HIGH or CRITICAL finding. In addition, Kubernetes aggregated ClusterRoles currently
appear both as rules in their parent and as separate latent definitions; resolving
`aggregationRule` before event generation would remove that duplication.

The proposed follow-up schema therefore keeps full findings as structured `Evidence` but
renders one compact event per resolved grant. Its technical `Severity` is the strongest
attack path; its review `Priority` additionally considers subject exposure, scope,
new/changed state, constraints and an explicitly approved baseline. Risk count does not
raise severity by itself. Subsequent scheduled scans should emit lifecycle changes
(`new`, `changed`, `risk_increased`, `resolved`) plus one scan summary instead of sending
an unchanged full snapshot. This follow-up is design guidance from the validation and is
not yet implemented.

Docker Desktop's existing network and non-shared `/sys/fs/bpf` mount prevented a safe
Cilium datapath takeover. The test therefore kept Docker Desktop's CNI and ran Cilium in
controller/RBAC compatibility mode with CNI installation, policy enforcement, Envoy and
the unmanaged-pod restarter disabled. This limitation is recorded explicitly rather than
claiming a full Cilium networking test.

Reproducible manifests, the full report and the detailed test notes are under
[`artifacts/live-cluster-2026-08-06`](artifacts/live-cluster-2026-08-06/):

- [`live-test-summary.md`](artifacts/live-cluster-2026-08-06/live-test-summary.md)
- [`kubiscan-rbac-events-final.json`](artifacts/live-cluster-2026-08-06/kubiscan-rbac-events-final.json)
- [`mock-rbac.yaml`](artifacts/live-cluster-2026-08-06/mock-rbac.yaml)
- [`nginx-demo.yaml`](artifacts/live-cluster-2026-08-06/nginx-demo.yaml)
- [`kubiscan-live-job.yaml`](artifacts/live-cluster-2026-08-06/kubiscan-live-job.yaml)

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
| `summary` | optional short verb phrase used in a risk-event Summary, e.g. `read Kubernetes Secrets` |
| `description` | optional first sentence of `Why`; the exact matched permission is the fallback |
| `impact` | optional consequence shown after `description`; category text is the fallback |
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
