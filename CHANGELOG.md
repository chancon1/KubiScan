# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).


## [Unreleased]

Context-aware risk matrix. A finding's severity is now decided by where the
permission was actually granted, not by a constant attached to the pattern.

### Added
- Binding-centred risk events (`--risk-events`). One event represents one risky
  pattern through one concrete RoleBinding or ClusterRoleBinding, so two grants
  of the same ClusterRole no longer share a report record or explanation.
- Structured event schema v2 with human-readable `Summary`, `Status`, `Risk`,
  `Granted To`, matched `Permission`, `Role`, `Binding`, `Scope` and `Why` fields.
  Multivalue fields remain JSON arrays instead of newline-delimited display text.
- Stable SHA-256 `event_id` based on pattern, role and binding for tracking the same
  grant across scans. Cluster context remains the responsibility of the log collector.
- `ACTIVE` and `LATENT` event states. A binding with no subjects is latent and is
  scored as an unbound grant rather than as active cluster-wide access.
- Optional `summary`, `description` and `impact` vocabulary on matrix patterns;
  patterns without it fall back to the exact permissions that matched.
- `KUBISCAN_REPORT_MODE=events|roles` migration switch in the in-cluster entrypoint.
  The event schema is the default; `roles` restores the previous JSON contract.
- Context scoring engine (`engine/scoring.py`). Seven modifiers adjust a
  pattern's base priority and are applied in a fixed order, clamped to
  LOW..CRITICAL: `clusterWide`, `namespacedBindingOnly`, `sensitiveNamespace`,
  `boundToEveryone`, `privilegedSaReachable`, `resourceNamesRestricted`,
  `unbound`. A match never decays to NONE - context can make a finding less
  urgent, but the permission is still there.
- `engine/scan_context.py` - binding index built once per scan, sensitive
  namespace list, privileged service-account map, and `SingleBindingContext`
  for scoring one binding in isolation.
- Two-pass scan (`scan_roles_and_clusterroles`). The first pass scores
  everything except `privilegedSaReachable`; the map of already-critical
  service accounts is built from its result, then the second pass settles the
  affected findings. The map is never consulted while it is being built.
- `engine/finding.py` - `Finding`, `RuleMatch` and `AppliedModifier`. A finding
  renders as one line - `risky-secrets-read: HIGH -> CRITICAL (clusterWide)` -
  which is what the report and the JSON events carry. The findings are read as
  Splunk events, one field per line, so a four-line block per matched pattern
  pushed the rest of the event off the screen: a role matching six patterns
  spent 24 lines saying what now takes six.
- `--explain` restores the full block per finding: the matched rules with their
  apiGroup and one line per modifier with its delta and reason.
- `engine/risky_pattern.py` - a matrix entry is a pattern, not a `Role`.
- `sensitive_namespaces.yaml` plus `--sensitive-namespaces` and
  `--sensitive-namespaces-add` to replace or extend the shipped list.
- `profiles:` block in `risky_roles.yaml`; patterns gained `scope`, `appliesTo`,
  `profile`, `modifiers`, `category` and `matchesAnyApiGroup`.
- Matrix grew from 80 to 170 patterns across 10 categories, 76 of them
  cluster-scoped.
- Test suite under `tests/` (`python tests/run_all.py`, no cluster needed).
  `tests/fixtures/detected_permissions.txt` baselines all 553 permissions the
  matrix can detect, so losing one shows up as a deleted line rather than as
  silence. One guard is there for the log pipeline rather than for the model:
  every string a report can emit - pattern names, categories, modifier names
  and their explanations - must stay ASCII, since the findings are parsed
  downstream by a log collector.
- Reproducible live-cluster validation artifacts under
  `artifacts/live-cluster-2026-08-06`: mock RBAC, nginx workload and Ingress,
  in-cluster Job manifest, full 471-event JSON report, and an execution summary.
  The Job completed successfully and every stdout line parsed as one schema-v2
  event without an embedded cluster-name field.

### Known limitations
- Schema v2 emits one event per matched pattern and concrete binding, then sends
  the full snapshot on every Job run. The live test showed 471 events from only
  59 risky roles, including 224 Kyverno events. The documented follow-up is one
  compact event per resolved Role+Binding, full findings kept as structured
  evidence, change-only lifecycle emission, and a separate scan summary.
- Kubernetes ClusterRole aggregation is not resolved before event generation.
  Aggregated component roles can therefore appear as separate `LATENT` events
  while their rules also appear in the bound parent role.
- Potential impact and review urgency are both represented by `Priority` today.
  The follow-up design separates technical `Severity` from context/baseline-aware
  review `Priority`; this has not yet changed the schema or scorer.

### Changed
- The in-cluster Job now emits one JSON object per binding-centred risk event.
  Legacy CLI reports and their JSON schema are unchanged.
- Event system filtering hides only a `system:*` role reached through a
  `system:*` binding. A custom binding to a built-in role remains visible.
- RoleBindings and ClusterRoleBindings are scored per binding rather than
  inheriting the role's worst case. A ClusterRole granting
  `create clusterrolebindings` is critical behind a ClusterRoleBinding and
  inert behind a namespaced RoleBinding.
- The binding reports (`-rb`, `-rcb`, `-rab`) explain their own verdict. Their
  `Triggered By` column used to be empty, which left the one report that can
  name the guilty binding - ten RoleBindings at HIGH and the single
  ClusterRoleBinding at CRITICAL - with no reason attached to either number.
  Each binding now carries the same arithmetic the role level shows, scored in
  its own scope: `CRITICAL -> HIGH`, `-1 namespacedBindingOnly`.
- Bound subjects are read from the scan context instead of being recomputed in
  each print function; removed four duplicated blocks from `KubiScan.py`.
- The scan is memoised, so the several report switches of one run no longer
  each re-read the whole cluster.
- `is_rule_contains_risky_rule` returns a `RuleMatch` carrying the source rule
  and the matched verbs instead of a bool - scoring needs the verbs to tell
  whether a `resourceNames` restriction narrows anything.

### Fixed
- The `Rules` column no longer ends in a stray newline, which rendered as an
  empty line in the table and as a blank field line in the JSON events.
- The table caps its free-text columns at 55 characters and wraps instead of
  running past 250. The JSON export is taken before wrapping and keeps the full
  text.
- `apiGroups: ["*"]` in a pattern now means group-unrestricted access
  specifically, satisfied only by a source rule that also says `"*"`. Total
  control of one API group is expressed with `matchesAnyApiGroup: true`. The
  two were previously alike, which let the wildcard patterns swallow
  `apiGroups: [constraints.gatekeeper.sh], resources: ["*"]`.
- A pattern verb of `"*"` likewise requires `"*"` on the source rule.
- Patterns holding several rules are a strict AND. The old match counter could
  report success before every rule had been satisfied, which is what the
  escalation-chain patterns depend on.
- Cluster-scoped patterns are no longer evaluated against namespaced Roles. A
  Role granting `get nodes/proxy` grants nothing and is no longer reported.
- Dropped the `resourceNames` + `bind` recursion, which re-read roles from the
  cluster in the middle of rule matching.
- A role holding a full wildcard collapses into one finding instead of matching
  the whole matrix.

## [v1.6] - 2023-01-27
- Replaced Added support to match case match case with if else to support Python versions below 3.10 (#69 by @kamal2222ahmed)
- Failed chmod when not specifying AWS info (#66 & #67 by @elreydetoda)
- Adding support to AKS and options to CVE scan (#65 by @2niknatan)
- Adding CVE scan and unittest (#64 by @2niknatan)
- Adding flags (-o, -q, -j and -nc) to enhance the output (#63 by @2niknatan)
- Changing the risky pods function (#62 by @2niknatan)
- Adding unit tests (#55 by @2niknatan)
- Supporting eks in docker container (#54 by @2niknatan)
- Printing error message when no kind was entered to '-aars' flag (#53 by @2niknatan)
- Fixing duplicates in '-rp' flag (#52 & #50)
- Fix typo in api_client.py (#51 by @AlonBenHorin)
- Fixing '-rp' flag by adding logic so it can print several Service Accounts (#49 by @2niknatan)
- Adding secret creation to support version +1.24
- Fixing hang in some environments (#47 by @2niknatan)
- Fixing the path to '/opt/kubiscan/config_bak' like in the Dockerfile (#46 by @2niknatan)
- Adding an environment variable to docker file, fixing -td flag and catching exceptions and adding tag to docker image (#45 by @2niknatan)
- Update docker_run.sh
- Adding catch exception and fix non existing key bug (#41 by @AlonBenHorin)
- Fixing pull request #18 and adding bash script to run a container (#40 by @AlonBenHorin)
- Minor change in the check for running inside a container
- Added support to kubeconfig in the API client (by @g3rzi)
- Simplify dockerfile + Parameterize paths (#18 by @vidbina)

## [v1.5] - 2022-09-21
- Fix 'NoneType' object is not iterable and always connection to localhost (#24)
- Resolve errors encountered running kubiscan in openshift and from a container image (#23)
- Handle pod.spec.volumes with None (#20)
- Fix TLS warnings when using a token (#19)
- Fix SyntaxWarning for 'is not' with literals
- Fix missing namespace for service account (#10)
- Fix --pods-secrets-env example (#17)
- Support Py version where async is keyword: fix #11 (#14)
- Added fix for container check in MacOS (#15)
- Use yaml.safe_load instead of yaml.load (#16)
  
## [v1.4] - 2020-01-14
- Added check for hostPID and hostIPC
- Added parsing for pod's spec for hostPID nad hostIPC
- Added support on hostNetwork nad hostPorts
- Added printing of hostPorts and hostNetwork information
- Removed debug printing for pod name
- Fixed wrong indents in risk YAML file
- Added support on hostPaths in containers
- Added support to printing volumes with hostPaths mounted to container
- Added the mounted path inside the container

## [v1.3] - 2019-07-24
- Fix checking if inside a docker container
- Fix bug to get RoleBindings of "User" subjects
- Added catch for error 404 in function get_roles_associated_to_subject

## [v1.2] - 2019-04-10
- New switch (-pp\--privileged-pods) to get privileged pods\containers
- Added pod's namespace to risky pods
  
## [v1.1] - 2019-03-28
- New switch (-d\--deep) to read tokens from containers
- Added option to read token from ETCD
- Added missing verb in kubiscan-sa token permissions
- Fixed wrong resource name in kubiscan-sa token permissions
- New switch for priority filtering
- Support for different contexts
- Dockerfile support for lightweight alpine image
- Strip newline from files

## [v1.0] - 2019-03-28
- Initial version
