# Guards on the risk matrix

```bash
python tests/run_all.py
```

No cluster needed. Everything runs against `risky_roles.yaml` and the scoring
engine directly, so it is safe in CI and on a laptop.

## What each check is for

**`test_no_detection_lost`** is the important one. Editing the matrix is easy to
get wrong in exactly one direction: a verb quietly disappears from a pattern, the
scan still runs, the report still looks full, and a permission is simply no
longer detected. `fixtures/detected_permissions.txt` records every permission the
matrix can detect on its own, so losing one shows up in review as a deleted line
rather than as silence.

If you deliberately drop a permission, regenerate the fixture and say why in the
commit message:

```bash
python tests/build_baseline.py
```

**`test_every_pattern_is_reachable`** builds a role from each pattern's own rules
and checks the pattern fires on it. This is tautological by design - its job is
to catch patterns that are shadowed by an earlier one, or whose apiGroup or verb
list is malformed. It found two dead Gatekeeper patterns being swallowed by the
wildcard pattern.

**`test_negative_matching`** checks a pattern stays quiet on what it does not
cover: read verbs must not trigger write patterns, a vendor CRD called `secrets`
must not be mistaken for the core Secret, a cluster-scoped resource in a
namespaced Role grants nothing and must not be reported, and half of an
escalation chain is not the chain.

**`test_scoring`** pins each context modifier to its own condition. The failure
mode that matters is a modifier firing slightly too often - severities inflate
until the top of the report means nothing again, which is the problem the
scoring model exists to fix.

## Traps this codebase has already fallen into

- **Several resources in one pattern rule behave as AND.** A rule listing
  `["certificates", "certificaterequests"]` only matches a role holding *both*.
  Write one pattern per resource. `test_no_detection_lost` catches this.
- **Multiple rules in one pattern also behave as AND**, and that one is
  intentional - it is how the escalation-chain patterns work. Those are excluded
  from the baseline, since no single permission of a chain is detectable alone.
- **`apiGroups: ["*"]` in a pattern means group-unrestricted access**, not "any
  group". Use `matchesAnyApiGroup: true` when you mean the latter.
- **`resourceNames` narrows more verbs than it looks like.** Only `create` and
  collection requests ignore it. `use`, `bind`, `escalate`, `impersonate` and
  `approve` are all narrowed - and they are the dangerous ones.

## What these tests do not tell you

They lock in *behaviour*, not *judgement*. Whether `create pods` deserves a HIGH
base rather than MEDIUM, and whether a sensitive namespace is worth exactly one
level, are policy decisions that no assertion can settle. Change them in
`risky_roles.yaml` profiles when the ranking is wrong; the tests will tell you
what else moved.

They also cannot verify that a third-party pattern names its API group
correctly. If `argoproj.io` were misspelled, the pattern would still be
"reachable" - the test builds its probe from the same wrong string. Only a live
install of that product proves the group and resource names are right.
