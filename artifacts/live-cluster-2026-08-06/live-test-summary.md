# KubiScan live Kubernetes test — 2026-08-06

## Environment

- Kubernetes context: `docker-desktop`
- Kubernetes: `v1.36.1`
- Node: one `Ready` control-plane node, no taints
- KubiScan source: branch `codex/rbac-risk-events`, commit `f2b2ab2`
- Test image: `kubiscan:rbac-risk-events-live`

The Kubernetes context is recorded only in this external test summary. KubiScan events do
not contain a cluster-name field; the log collector remains responsible for that context.

## Installed software

| Component | Chart | Application | Result |
|---|---:|---:|---|
| Kyverno | `3.8.2` | `v1.18.2` | Four controllers `Running`, 4/4 ready |
| ingress-nginx | `4.15.1` | `1.15.1` | Controller `Running`, 1/1 ready |
| Cilium | `1.19.6` | `1.19.6` | Operator `Running`, controller/RBAC compatibility mode |
| cert-manager | `v1.21.1` | `v1.21.1` | Controller, webhook and cainjector `Running`, 3/3 ready |
| nginx demo | manifest | `nginx:1.28.0-alpine` | Deployment 1/1 ready; ingress returned HTTP 200 |

Docker Desktop already owns the cluster network and does not expose a node PodCIDR. A
normal Cilium takeover also failed because `/sys/fs/bpf` is not a shared mount. To avoid
breaking the cluster, Cilium was kept installed with its CRDs, RBAC and operator, while
the datapath agent was disabled using an unmatched node selector. The effective safety
settings are:

```yaml
cni.install: false
cni.exclusive: false
kubeProxyReplacement: false
policyEnforcementMode: never
envoy.enabled: false
operator.unmanagedPodWatcher.restart: false
agentNotReadyTaintKey: ""
```

## Mock RBAC

The `kubiscan-risk-lab` namespace contains three ServiceAccounts and six deliberately
risky grants/definitions:

1. `system:authenticated` can create/update/patch ClusterRoleBindings.
2. `ci-deployer` has wildcard API access cluster-wide.
3. `security-auditor` can impersonate users cluster-wide.
4. `secret-reader` can read all Secrets in `kubiscan-risk-lab`.
5. `mock-developer@example.test` can create `pods/exec` requests in the namespace.
6. `kubiscan-mock-latent-pod-creator` can create Pods but has no binding.

`kubectl auth can-i` confirmed the five active grants. The latent role has zero bindings.

## KubiScan execution

The in-cluster Job `kubiscan/kubiscan-live-test-20260806` completed successfully in six
seconds with no restart. Its stdout contained 471 lines, and every line parsed as one
`rbac_risk` JSON event.

- Schema versions: only `2`
- Events: `471`
- Unique non-empty event IDs: `471`
- Events containing `Cluster Name`: `0`
- `CRITICAL`: `104`
- `HIGH`: `99`
- `MEDIUM`: `98`
- `LOW`: `170`
- `ACTIVE`: `252`
- `LATENT`: `219`

## Mock findings in review order

| Order | Priority | Status | Finding |
|---:|---|---|---|
| 1 | CRITICAL | ACTIVE | All authenticated users can create or modify ClusterRoleBindings cluster-wide |
| 60 | CRITICAL | ACTIVE | `ci-deployer` can use unrestricted Kubernetes API permissions cluster-wide |
| 61 | CRITICAL | ACTIVE | `security-auditor` can impersonate users cluster-wide |
| 186 | HIGH | ACTIVE | `secret-reader` can read Kubernetes Secrets in `kubiscan-risk-lab` |
| 187 | HIGH | ACTIVE | `mock-developer@example.test` can create `pods/exec` in the namespace |
| 301 | MEDIUM | LATENT | Unbound Role can create Pods |

The ordering behaves as intended: a grant to every authenticated user is first; active
cluster-wide grants precede active namespaced grants; the unbound definition is kept but
placed below active risks.

## Observations

- Installed operators generated real findings: Kyverno 224, cert-manager 46, Cilium 19,
  and ingress-nginx 7 events in the pre-Job scan.
- cert-manager legitimately needs broad Secret, Pod and Ingress permissions, so several
  of its events are CRITICAL. This is technically accurate capability analysis, but a
  production triage layer will need trusted-component/baseline context to distinguish an
  expected operator grant from an unexpected grant with the same capability.
- The first mock risk proves that broad subject exposure affects review order, not just
  the permission itself.

## Scale finding and follow-up design

The 471 records are not driven by the 20 Pods in the cluster. They come from 59 risky
roles matching many matrix patterns through their bindings. The largest individual
contributors were `ClusterRole admin` (64 latent events), `ClusterRole edit` (49 latent),
`ClusterRole storage-provisioner` (45 active), and two Kyverno admission roles (32 each).

Kyverno produced 224 pattern events from 19 unique roles. Grouping by resolved
`Role + Binding` reduces those to 21 records: 11 active grants and 10 latent definitions.
Across the whole report, grant grouping reduces 471 records to 62; only 40 grouped grants
are active and contain a HIGH or CRITICAL finding.

Several Kyverno `*:core` ClusterRoles feed bound parent roles through Kubernetes
`aggregationRule`. Schema v2 reports their rules in the parent and also treats the source
roles as latent definitions. A future implementation must resolve the aggregation graph
first and keep source roles as evidence rather than separate review events.

The agreed follow-up design is:

1. One compact event per resolved Role+Binding; different bindings remain different
   events because they grant access to different subjects or scopes.
2. Full pattern matches remain a structured `Evidence` array. Human output shows one
   summary, at most three top risk groups, and at most three short reasons.
3. `Severity` represents the strongest attack path. Review `Priority` additionally uses
   exposure, scope, new/changed state, constraints and an explicitly approved baseline.
   Risk count alone never raises severity.
4. A first-seen grant is not trusted by controller name. Approval stores a fingerprint of
   rules, binding and subjects; drift makes it reviewable again.
5. Scheduled scans emit `new`, `changed`, `risk_increased` and `resolved` records plus a
   scan summary instead of resending an unchanged full snapshot.

These points document the outcome of the live test and the next iteration. They are not
implemented in schema v2 yet.

## Reproduction

```powershell
kubectl apply -f artifacts/live-cluster-2026-08-06/mock-rbac.yaml
kubectl apply -f artifacts/live-cluster-2026-08-06/nginx-demo.yaml
docker build -t kubiscan:rbac-risk-events-live .
kubectl apply -f artifacts/live-cluster-2026-08-06/kubiscan-live-job.yaml
kubectl wait --for=condition=complete job/kubiscan-live-test-20260806 -n kubiscan --timeout=45s
kubectl logs job/kubiscan-live-test-20260806 -n kubiscan
```

The mock roles are intentionally unsafe and should not be left in a shared or production
cluster after testing.
