# Authorization Engine Design

Status: Implemented — initial `v0.2.0` scope
Target release: `v0.2.0`
Primary owner: Parakh Shinde
Last updated: 2026-08-30

## Implementation status

The initial authorization-engine scope is implemented and integrated into attack-path detection.

Implemented capabilities include:

- inherited allow-policy evaluation;
- inherited deny-policy evaluation;
- deny-rule principal and permission exceptions;
- explicit `ALLOW`, `DENY`, and `UNKNOWN` decisions;
- structured and deterministic decision evidence;
- conservative handling of unsupported conditions;
- authorization-aware IAM-policy escalation;
- authorization-aware service-account key creation;
- authorization-aware `actAs` and Compute Engine paths;
- authorization-aware multi-hop impersonation;
- end-to-end deny-policy CLI integration tests.

The implementation does not claim complete parity with Google Cloud authorization. Full CEL evaluation, principal access boundaries, group expansion, organization-policy constraints, and product-specific authorization remain future work.

## Summary

GCP IAMGraph currently determines effective access from inherited IAM allow-policy bindings and role permissions. This is sufficient for identifying many privilege-escalation paths, but it does not model every policy type that participates in Google Cloud authorization.

The authorization engine will introduce an explicit policy-decision layer between policy ingestion and attack-path detection.

The engine will answer:

> Can this principal use this permission on this resource, and why?

Every evaluation will return one of three decisions:

- `ALLOW`
- `DENY`
- `UNKNOWN`

The result will include the policies, grants, restrictions, conditions, and hierarchy relationships that contributed to the decision.

## Motivation

An allow binding alone does not prove that a principal can successfully use a permission.

Effective access can also be affected by:

- inherited deny policies;
- deny-rule exceptions;
- IAM Conditions;
- principal access boundary policies;
- unsupported or incomplete policy data.

Without these policy types, an attack-path analyzer can produce false-positive paths by treating a permission as usable when another policy blocks it.

The authorization engine will make access decisions explicit, deterministic, testable, and explainable.

## Goals

The authorization engine must:

1. Evaluate inherited allow-policy grants.
2. Evaluate inherited deny-policy rules.
3. Make applicable deny rules override allow grants.
4. Support deny-rule principal exceptions.
5. Support deny-rule permission exceptions.
6. Preserve and report IAM Conditions.
7. Return `UNKNOWN` when a required condition cannot be evaluated safely.
8. Produce structured evidence for every decision.
9. Prevent denied or unknown permissions from silently creating confirmed attack paths.
10. Remain deterministic across repeated runs.
11. Support future principal access boundary evaluation.
12. Preserve compatibility with existing detection rules during migration.

## Non-goals for the first implementation

The first `v0.2.0` implementation will not:

- modify Google Cloud policies;
- authenticate to Google Cloud;
- evaluate every Common Expression Language expression;
- expand Google Group membership;
- implement organization-policy constraints;
- implement product-specific ACLs;
- automatically remediate denied or allowed access;
- claim complete parity with Google Cloud IAM authorization.

Unsupported semantics must result in `UNKNOWN`, not an assumed `ALLOW`.

## Design principles

### Deny by evidence, not by assumption

The engine must only return `DENY` when an applicable deny rule is identified.

### Allow by evidence, not by absence of denial

The engine must only return `ALLOW` when at least one effective allow grant contains the requested permission and no applicable restriction blocks it.

### Unknown must remain visible

Incomplete input, unsupported conditions, or unsupported policy constructs must produce `UNKNOWN`.

### Explain every decision

Every result must describe:

- principal;
- permission;
- resource;
- decision;
- allow evidence;
- deny evidence;
- condition status;
- policy source;
- inheritance path;
- evaluation notes.

### Deterministic output

The same normalized input must produce the same decision and evidence ordering.

## Terminology

### Principal

An identity requesting access, such as:

- user;
- service account;
- group;
- domain;
- workforce identity;
- workload identity;
- public principal.

### Permission

A Google Cloud permission such as:

```text
resourcemanager.projects.setIamPolicy
```

### Resource

The target Google Cloud organization, folder, project, service account, or product resource.

### Allow grant

An effective IAM binding whose role contains the requested permission.

### Deny rule

A policy rule that prevents selected principals from using selected permissions.

### Policy source

The resource where a policy or binding was defined.

### Target resource

The resource on which access is being evaluated.

## Decision model

The engine will define:

```python
class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN = "unknown"
```

An applicable deny rule takes precedence over an allow grant.

Decision order:

| Priority | Situation | Result |
| --- | --- | --- |
| 1 | Applicable explicit deny | `DENY` |
| 2 | Relevant policy cannot be evaluated safely | `UNKNOWN` |
| 3 | At least one effective allow grant | `ALLOW` |
| 4 | No effective allow grant | `DENY` |

The final case is an implicit denial and must be distinguishable from an explicit deny-policy result.

## Condition model

Conditions use three-valued evaluation:

```python
class ConditionState(str, Enum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"
```

For an allow binding:

- `TRUE` contributes an allow grant.
- `FALSE` does not contribute an allow grant.
- `UNKNOWN` can cause the final result to become `UNKNOWN`.

For a deny rule:

- `TRUE` applies the denial.
- `FALSE` skips the denial.
- `UNKNOWN` produces `UNKNOWN` unless another unconditional deny already proves `DENY`.

## Proposed data model

### DenyRule

```python
@dataclass(frozen=True)
class DenyRule:
    denied_principals: tuple[str, ...]
    exception_principals: tuple[str, ...]
    denied_permissions: tuple[str, ...]
    exception_permissions: tuple[str, ...]
    condition: dict[str, Any] | None = None
```

### DenyPolicy

```python
@dataclass(frozen=True)
class DenyPolicy:
    name: str
    parent: str
    display_name: str
    rules: tuple[DenyRule, ...]
```

### EvaluationRequest

```python
@dataclass(frozen=True)
class EvaluationRequest:
    principal: str
    permission: str
    resource: str
    context: dict[str, Any] | None = None
```

### DecisionEvidence

```python
@dataclass(frozen=True)
class DecisionEvidence:
    evidence_type: str
    source: str
    description: str
    inherited: bool
    condition_state: ConditionState | None = None
```

### EvaluationResult

```python
@dataclass(frozen=True)
class EvaluationResult:
    request: EvaluationRequest
    decision: Decision
    explicit_deny: bool
    allow_grants: tuple[Grant, ...]
    deny_evidence: tuple[DecisionEvidence, ...]
    notes: tuple[str, ...]
```

## Public interface

```python
class AuthorizationEngine:
    def evaluate(
        self,
        principal: str,
        permission: str,
        resource_name: str,
        context: dict[str, Any] | None = None,
    ) -> EvaluationResult:
        ...
```

A convenience method may be provided:

```python
def is_allowed(...) -> bool:
    ...
```

`is_allowed()` must return `True` only when the decision is exactly `ALLOW`. It must return `False` for `DENY` and `UNKNOWN`.

Security-sensitive detections should use `evaluate()` directly so they can distinguish blocked access from incomplete analysis.

## Evaluation algorithm

For each request, the engine will:

1. Validate the principal, permission, and resource.
2. Resolve the target resource in the hierarchy.
3. Collect effective allow bindings from the resource and its ancestors.
4. Resolve the permissions belonging to each role.
5. Evaluate allow-binding conditions.
6. Collect deny policies from the resource and its ancestors.
7. Match the principal against deny rules.
8. Apply principal exceptions.
9. Match the requested permission against denied permissions.
10. Apply permission exceptions.
11. Evaluate deny-rule conditions.
12. Combine the evidence into a final decision.
13. Sort all evidence deterministically.
14. Return a structured evaluation result.

## Deny-rule matching

A deny rule applies when:

1. The principal matches a denied principal.
2. The principal does not match an exception principal.
3. The permission matches a denied permission.
4. The permission does not match an exception permission.
5. The rule is unconditional or its condition evaluates to `TRUE`.

The first implementation will support exact principal and permission matching.

Wildcard permissions, principal sets, and advanced condition behavior will be added only with dedicated specifications and tests.

## Hierarchy behavior

Allow bindings and deny policies can be inherited through:

```text
organization
→ folder
→ project
→ child resource
```

Every inherited policy item must preserve:

- policy source;
- target resource;
- inheritance status;
- hierarchy path.

The evaluator must reject unknown resources, unknown parents, and hierarchy cycles before evaluating access.

## Attack-path integration

Migration will happen in two phases.

### Phase 1: Compatibility

- Keep `AccessIndex.has_permission()`.
- Introduce `AuthorizationEngine.evaluate()`.
- Test the authorization engine independently.
- Preserve all existing findings.

### Phase 2: Enforcement

- Route security-sensitive permission checks through the evaluator.
- Continue a confirmed path only when the decision is `ALLOW`.
- Stop a path when the decision is `DENY`.
- Represent `UNKNOWN` paths separately.
- Attach authorization evidence to findings.

A denied permission must never appear as a confirmed exploitable attack-path edge.

## Explanation example

Request:

```text
principal: user:developer@example.test
permission: resourcemanager.projects.setIamPolicy
resource: projects/payments-prod
```

Result:

```text
decision: DENY
explicit_deny: true

allow evidence:
- roles/resourcemanager.projectIamAdmin inherited from folders/engineering

deny evidence:
- policies/deny-project-iam attached to organizations/987654
- denied permission: resourcemanager.projects.setIamPolicy
- denied principal: user:developer@example.test

explanation:
The principal receives the permission through an inherited allow binding,
but an inherited deny policy blocks the permission.
```

## Input schema

IAMGraph JSON will gain a top-level `deny_policies` array:

```json
{
  "resources": [],
  "role_definitions": [],
  "deny_policies": [
    {
      "name": "policies/deny-project-iam",
      "parent": "organizations/987654",
      "display_name": "Deny project IAM changes",
      "rules": [
        {
          "denied_principals": [
            "user:developer@example.test"
          ],
          "exception_principals": [],
          "denied_permissions": [
            "resourcemanager.projects.setIamPolicy"
          ],
          "exception_permissions": []
        }
      ]
    }
  ]
}
```

Documents without `deny_policies` remain valid and default to an empty collection.

Malformed deny policies must raise `InputError` with an actionable message.

## Error handling

The engine must handle:

- unknown resources;
- empty principals;
- empty permissions;
- deny policies with unknown parents;
- invalid rule structures;
- non-array principal fields;
- non-array permission fields;
- hierarchy cycles;
- unsupported policy versions.

Structurally valid but unsupported semantics should produce `UNKNOWN` instead of causing a crash or assumed access.

## Determinism

Deny evidence will be sorted by:

```text
policy name
→ rule position
→ source resource
→ permission
→ principal
```

Allow evidence will be sorted by:

```text
source resource
→ role
→ principal
→ target resource
```

Results must not depend on dictionary order, set iteration, filesystem order, or parser insertion order.

## Performance requirements

Initial targets:

| Dataset | Target |
| --- | --- |
| 1,000 resources | Under 1 second |
| 10,000 bindings | Under 2 seconds |
| 100,000 grants | Under 10 seconds |
| Repeated requests | Reuse indexed policy data |

The evaluator should index:

- policies by resource;
- rules by principal;
- rules by permission;
- permissions by role;
- resource ancestry.

Benchmarks will be added after semantic correctness is established.

## Security requirements

The engine must:

- remain read-only;
- avoid network access during offline analysis;
- never log credentials;
- avoid exposing complete confidential policies in errors;
- bound graph traversal;
- detect hierarchy cycles;
- reject malformed input;
- preserve unknown decisions;
- avoid automatic remediation.

## Observability requirements

Future deployments should measure:

- evaluation count;
- evaluation latency;
- decision totals;
- unknown-decision totals;
- parser failures;
- policy count;
- resource count;
- attack-path count;
- graph-construction latency.

Metric labels must not include raw principals, resource names, credentials, or confidential policy content.

## Testing strategy

### Unit tests

Test:

- unconditional explicit deny;
- inherited deny;
- principal exception;
- permission exception;
- unrelated deny rule;
- allow without deny;
- no allow grant;
- unknown resource;
- condition `TRUE`;
- condition `FALSE`;
- condition `UNKNOWN`;
- deterministic evidence ordering.

### Integration tests

Test:

- organization deny overriding project allow;
- folder deny overriding resource allow;
- exception restoring access;
- deny stopping service-account impersonation;
- deny stopping project IAM escalation;
- malformed deny-policy input;
- JSON and SARIF decision evidence.

### Regression tests

All existing 27 tests must continue to pass during the compatibility phase.

### Future property tests

Verify:

- adding an applicable deny cannot produce `ALLOW`;
- removing an allow cannot create `ALLOW`;
- input ordering does not change a decision;
- duplicate policies do not duplicate evidence;
- hierarchy traversal always terminates.

## Implementation milestones

### Milestone 1: Models and parser

- Add `DenyRule`.
- Add `DenyPolicy`.
- Parse IAMGraph deny policies.
- Validate parents and rule fields.
- Add model and parser tests.

### Milestone 2: Authorization evaluator

- Add decision types.
- Add request and result types.
- Implement allow evaluation.
- Implement deny evaluation.
- Generate structured evidence.
- Add evaluator tests.

### Milestone 3: Detection integration

- Route permission-based detections through the evaluator.
- Prevent denied permissions from producing findings.
- Represent unknown paths separately.
- Add regression tests.

### Milestone 4: Cloud Asset Inventory

- Parse supported deny-policy assets.
- Preserve unsupported fields.
- Add realistic CAI fixtures.
- Document ingestion limitations.

### Milestone 5: Hardening

- Add benchmarks.
- Add fuzz tests.
- Add threat model.
- Add detection specifications.
- Raise authorization-core coverage toward 95%.

## Backward compatibility

Existing IAMGraph documents without deny policies must continue to work.

Existing CLI commands and report formats must remain compatible unless a separately documented schema version is introduced.

## Acceptance criteria

The first authorization-engine release is complete when:

1. Existing 27 tests continue to pass.
2. New deny-policy tests pass.
3. Coverage remains above the enforced threshold.
4. An organization deny overrides a project allow.
5. Principal exceptions work.
6. Permission exceptions work.
7. Unsupported relevant conditions produce `UNKNOWN`.
8. Denied permissions cannot create confirmed attack paths.
9. Decisions contain deterministic evidence.
10. Reports preserve decision explanations.
11. Supported and unsupported semantics are documented.
12. CI passes on Python 3.10, 3.11, and 3.12.

## Alternatives considered

### Continue using permission lookup only

Rejected because a permission grant does not represent the complete authorization decision.

### Treat unsupported policies as no effect

Rejected because this could create inaccurate confirmed attack paths.

### Return only a Boolean

Rejected because a Boolean cannot distinguish explicit denial, implicit denial, and incomplete evaluation.

### Implement live collection first

Deferred because scaling incomplete authorization semantics would scale inaccurate decisions.

## Future work

- broader IAM Conditions evaluation;
- principal access boundary policies;
- Google Group expansion;
- predefined-role synchronization;
- live read-only Cloud Asset Inventory collection;
- Terraform IAM ingestion;
- incremental analysis;
- large-environment benchmarks;
- interactive decision explanations;
- policy-difference analysis.

## References

- [Google Cloud IAM policy types](https://cloud.google.com/iam/docs/policy-types)
- [Google Cloud IAM deny policies](https://cloud.google.com/iam/docs/deny-overview)
- [Google Cloud IAM Conditions](https://cloud.google.com/iam/docs/conditions-overview)
- [Google Cloud principal access boundary policies](https://cloud.google.com/iam/docs/principal-access-boundary-policies)
- [Cloud Asset Inventory overview](https://cloud.google.com/asset-inventory/docs/asset-inventory-overview)
- [Google Cloud IAM policy evaluation](https://cloud.google.com/iam/docs/policy-types#policy_evaluation)