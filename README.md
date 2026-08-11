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
  - [Grant-centred risk events](#grant-centred-risk-events)
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
- Run as an in-cluster Job and emit one JSON event per resolved RBAC grant for log
  collectors

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

### Grant-centred risk events

`--risk-events` is the compact log-collector view. It emits one event per **distinct risk
verdict** — one role, one way of being granted, and everybody who holds it that way:

```
python3 KubiScan.py --risk-events
python3 KubiScan.py --risk-events -j report.json
```

Grants that score identically share one event and are counted, so a ClusterRole handed to
five hundred accounts through five hundred RoleBindings is one review decision rather than
five hundred records. What splits an event out is a *different verdict* — a
ClusterRoleBinding among the RoleBindings, or a grant that landed in a sensitive
namespace — which is exactly the set worth looking at.

```json
{
  "event_type": "rbac_grant",
  "event_id": "51d3849de83b23e68084d35e470db11889eb74faa47a674f5c80711029681c89",
  "Summary": "500 subjects can exec into running containers, each in its own namespace",
  "Priority": "HIGH",
  "Severity": "HIGH",
  "Status": "ACTIVE",
  "Kind": "ClusterRole",
  "Name": "namespace-developer",
  "Namespace": null,
  "Scope": "500 namespaces, all via RoleBinding",
  "Grant Count": "500 subjects, 500 bindings in 500 namespaces",
  "Bound Service Accounts": [
    "developer-001@team-001 [SA NS] (via RoleBinding: team-001/nsdev-001)",
    "developer-002@team-002 [SA NS] (via RoleBinding: team-002/nsdev-002)"
  ],
  "Bound Service Accounts Shown": "44 of 500",
  "RISK": [
    "HIGH     risky-pods-exec       [core] pods/exec: create",
    "HIGH     risky-cronjobs        [batch] cronjobs: create,update,patch",
    "MEDIUM   risky-configmaps-read [core] configmaps: get,list,watch"
  ],
  "Risk Count": 18,
  "Why": [
    "Creating Pods can mount namespace Secrets and use any ServiceAccount in that namespace.",
    "The permission can create or control executable workloads."
  ],
  "Creation Time": "2026-08-06T15:21:12Z"
}
```

`ACTIVE` means a binding currently grants the permission to at least one subject.
`LATENT` means either that the role is unbound or that the binding has no subjects. The
normal Role/ClusterRole and binding reports remain available and keep their old schema.

#### Event identity

`event_id` is derived from the role and its verdict, never from the members. Adding a
service account to a role that already has five hundred reads as the same event with a
bigger `Grant Count`, not as a new event on every scan — otherwise every scheduled scan
would look like a fresh finding and dedup in the collector would be useless. A grant that
scores differently does get its own id, because it is a different decision.

#### RISK

`RISK` is one flat value per finding — `SEVERITY  name  [apiGroup] resource: verbs` —
ordered strongest first. It is a multivalue field on purpose, so `RISK="risky-pods-exec"`
is searchable; a wrapped block of all findings in one string is neither readable nor
searchable.

#### How many accounts are listed

`Bound Service Accounts` is fitted to a **byte budget**, not to a fixed number of names.
A fixed cap cannot work: sixty accounts fit beside a role with 18 findings and overflow
beside one with 64, and long names halve it again. The list therefore fills until the
event reaches its budget, and `Grant Count` always reports the real total. When the list
was shortened, `Bound Service Accounts Shown` says so.

Splunk truncates a line at 10000 bytes by default and cuts the *tail*, which would leave
invalid JSON rather than a shortened list — hence the budget, which defaults to 8000 with
headroom. Raise it alongside the collector's own limit:

```
KUBISCAN_EVENT_BYTE_BUDGET=60000     # plus TRUNCATE = 65536 in props.conf
```

Measured on a role with 18 findings and 500 RoleBindings: 44 accounts listed at the
default budget, around 480 with the raised one.

#### Severity and Priority

The two scores answer different questions and are deliberately kept apart.

**`Severity`** is what the permission lets you do. Only modifiers that change the
capability itself move it: `resourceNamesRestricted`, `namespacedBindingOnly` and
`privilegedSaReachable`. The same rule is the same capability wherever it is bound.

**`Priority`** is what to review first. It additionally weighs where the grant lands and
who holds it — `clusterWide`, `sensitiveNamespace`, `boundToEveryone`, `unbound`.

Neither is a count. A grant holding twenty risky permissions is not worse than the worst
of them, so both take the strongest single finding; the other nineteen are evidence for
the decision, not multipliers of it. Review order is `Priority` first, with `Severity`
breaking its ties.

#### Volume and aggregated ClusterRoles

Schema v2 was pattern-granular: a role matching 20 patterns through one binding emitted 20
events. On the [live-cluster validation](#live-cluster-validation) that turned 59 risky
roles into 471 records, and one role bound to 500 accounts would have produced 500 copies
of the same decision. Grouping by verdict brings the same cluster to 49 events and 81 KB,
with no line over Splunk's default limit.

Kubernetes fills an aggregated ClusterRole's rules from every ClusterRole matching its
`aggregationRule` selectors, so those permissions would otherwise be reported twice: once
on the parent that is actually bound, once on each source as a latent definition. The
aggregation graph is resolved and a source is folded into its parent as an
`Aggregated From` entry.

Two kinds of source are never folded. One with a binding of its own is a grant somebody
holds. One that is an aggregated ClusterRole itself is a composition point — the built-in
`edit` carries the label feeding `admin`, but it has its own name, sources and bindings,
and burying it inside `admin` would hide the role people actually reason about.

Change-only emission and an approved baseline remain design guidance in the validation
section; they need state between runs and are not implemented.

System filtering is deliberately grant-aware in this view. Kubernetes' own `system:*`
role plus `system:*` binding pairs are hidden by default, but a custom binding to a
`system:*` role stays visible because it is a deliberate grant. `--include-system`
restores everything.

#### Escalation chains across several roles

Some patterns are chains: `risky-chain-pod-and-secrets` needs *both* "create pods" and
"read secrets". Matching one role at a time only finds those where a single role happens
to grant both legs, which is not how privileges usually accumulate — they arrive through
several bindings, and the subject holding them can do exactly what the one dangerous role
could.

`--risk-events` therefore also reports chains assembled from several roles. Such an event
belongs to a subject rather than to a role, and names which role supplied which leg:

```json
{
  "Summary": "ServiceAccount team-a/app can run a workload and read the credentials it can mount in namespace team-a, through 2 roles",
  "Priority": "CRITICAL",
  "Risk": "risky-chain-pod-and-secrets",
  "Granted To": ["ServiceAccount team-a/app"],
  "Role": "Role team-a/pod-runner + Role team-a/config-reader",
  "Binding": "RoleBinding team-a/rb-pods + RoleBinding team-a/rb-secrets",
  "Scope": "namespace team-a",
  "Why": [
    "No single role grants this; the subject assembles it from 2 separate grants.",
    "[core] pods: create comes from Role team-a/pod-runner via RoleBinding team-a/rb-pods.",
    "[core] secrets: get,list comes from Role team-a/config-reader via RoleBinding team-a/rb-secrets."
  ]
}
```

Legs are only combined where they actually meet. Permissions granted in different
namespaces never form a chain, because creating a Pod in one namespace reaches no Secret
in another; a ClusterRoleBinding applies everywhere and so joins every namespace, while a
RoleBinding joins only its own. Subjects are followed one at a time, since two subjects
sharing a binding do not pool their permissions. A chain a single role already grants is
left to that role's own event instead of being reported twice.

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

The **Moves** column says which score a modifier acts on. *Capability* modifiers change
what the permission can do and therefore move both `Severity` and `Priority`; *exposure*
modifiers change only how urgently it should be reviewed. See
[Severity and Priority](#severity-and-priority).

| Modifier | Fires when | Effect | Moves |
|---|---|---|---|
| `clusterWide` | A ClusterRoleBinding grants the ClusterRole, so the permission covers every namespace | +1 | exposure |
| `namespacedBindingOnly` | Only RoleBindings reference the ClusterRole. Binding a ClusterRole with a RoleBinding grants its namespaced rules inside that one namespace, so its **cluster-scoped** rules never take effect | -1 | capability |
| `sensitiveNamespace` | The grant lands in a namespace listed in `sensitive_namespaces.yaml`. Not applied on top of `clusterWide`, which already covers every namespace there is | +1 | exposure |
| `boundToEveryone` | A binding hands the role to `system:authenticated` or `system:unauthenticated` | +1 | exposure |
| `privilegedSaReachable` | The permission can run a workload in a namespace that hosts an already-critical service account. Creating a Pod lets you name any service account of that namespace as its identity | +1 | capability |
| `resourceNamesRestricted` | Every rule granting the permission is pinned to named objects — one unrestricted rule beside a pinned one earns no discount. RBAC reads the object name from the request path, so a pinned rule grants nothing for `list`, `watch`, `deletecollection` or a `create` of a top-level resource; a `create` of a subresource carries its parent's name and is narrowed normally | -1 | capability |
| `unbound` | Nobody holds the permission — either no binding references the role, or every binding that does has an empty subject list and therefore grants it to no one. A latent risk, not an active one | -1 | exposure |

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

`sensitive_namespaces.yaml` ships the list that `sensitiveNamespace` uses, grouped by what
the namespace actually holds: the Kubernetes control plane (`kube-system`, `kube-public`,
`kube-node-lease`), policy and runtime security (`kyverno`, `gatekeeper-system`,
`tetragon`, `trivy-system`, …), secret and certificate delivery (`cert-manager`,
`external-secrets`), ingress and mesh (`ingress`, `ingress-nginx`, `istio-system`,
`higress-system`, `kube-vip`), storage and backup (`longhorn-system`, `velero`,
`snapshotter`, …), observability (`monitoring`, `logging`, `splunk`, `victoria-metrics`,
`coroot`, …) and delivery (`argocd`, `argo-events`, `dragonfly-system`, …). The groups are
documentation only — the scanner flattens them into one set. Tune it to the cluster:

```
kubiscan -rar --sensitive-namespaces-add prod,payments      # extend the shipped list
kubiscan -rar --sensitive-namespaces prod,payments          # replace it entirely
```

An entry ending in `*` matches by **prefix**, which is how a distribution that names its
platform namespaces from one stem is covered without listing each one:

```yaml
  shturval:
    - 'shturval-*'        # shturval-monitoring, shturval-logging, ...
```

Everything else is an exact name on purpose — `infra` must not quietly cover
`infra-sandbox`. Note the separator: `shturval-*` matches `shturval-monitoring` but not
`shturvalx`, and not the bare stem `shturval`.

A prefix is only right when *every* namespace under it is platform infrastructure. If
application namespaces share the stem, they will be raised a level too and the modifier
stops meaning anything — list those namespaces individually instead.

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
account token, runs the grant-centred `--risk-events` report, and prints **one JSON
object per event** on stdout so a log collector can pick them up line by line:

```json
{
  "scan_timestamp": "2026-08-06T19:21:58Z",
  "event_type": "rbac_grant",
  "event_id": "f3632e37ed9f121bd6eaa2622d481fd6dcc570eca40008a12385423e92d63b4b",
  "Summary": "All authenticated users can create or modify ClusterRoleBindings cluster-wide",
  "Priority": "CRITICAL",
  "Severity": "CRITICAL",
  "Status": "ACTIVE",
  "Kind": "ClusterRole",
  "Name": "kubiscan-mock-public-rbac-editor",
  "Namespace": null,
  "Scope": "cluster-wide",
  "Grant Count": "1 subject, 1 binding",
  "Bound Service Accounts": [
    "system:authenticated [Group] (via ClusterRoleBinding: kubiscan-mock-public-rbac-editor)"
  ],
  "RISK": [
    "CRITICAL risky-clusterrolebindings-write      [rbac.authorization.k8s.io] clusterrolebindings: create,update,patch"
  ],
  "Risk Count": 1,
  "Why": [
    "Changing ClusterRoleBindings can grant roles across the entire cluster.",
    "Kubernetes prevents binding stronger roles unless the caller holds their permissions or has bind; review both permissions together.",
    "Cluster-wide via ClusterRoleBinding: kubiscan-mock-public-rbac-editor."
  ],
  "Creation Time": "2026-08-05T21:10:50Z"
}
```

The multivalue fields (`Bound Service Accounts`, `RISK`, `Why`) remain JSON arrays, so
Splunk can search an individual subject or risk without parsing display text. The event
itself is always one JSON line, so a collector never has to stitch one back together.

Beyond the scan timestamp the event carries nothing constant: no tool name, no schema
version, no section, no row number. One consequence is worth knowing - the shape is not
self-identifying, so a future change to it has to be coordinated with whatever reads the
index rather than being detected from the data. The Job is annotated for Splunk (`splunk.com/index`,
`splunk.com/sourcetype`); adjust or drop those annotations to suit your collector.

`event_id` is a stable SHA-256 fingerprint of pattern, role and binding. It stays the same
across scans so Splunk can track a grant whose priority changes. KubiScan deliberately does
not add a cluster field: Fluent Bit or the Splunk agent should attach that deployment
context. When correlating several clusters, use that external field together with
`event_id` as the unique key.

Events are printed in review order - priority, then severity, then active before latent,
then scope, sensitive namespace and subject exposure - so `CRITICAL/ACTIVE` cluster-wide
grants to broad groups come first. That order is not stamped on the event: a row number
changes whenever an unrelated role appears elsewhere in the cluster, and a log store
re-derives the ordering from whatever a query sorts by.

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
an unchanged full snapshot.

**Implemented since:** one event per distinct risk verdict, grants that
score alike counted rather than repeated, `aggregationRule` resolution, and the
`Severity`/`Priority` split — see
[grant-centred risk events](#grant-centred-risk-events). Re-running the same scan yields
49 events and 81 KB, the four Kyverno `*:core` source roles fold into their parents, and
no line exceeds the collector's default limit.

**Still design guidance, not implemented:** the approved baseline keyed on a fingerprint
of rules, binding and subjects, and change-only emission between scheduled scans. Both
need state carried between runs, which the Job does not have today.

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
