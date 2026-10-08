# MandateGraph architecture

## State model

MandateGraph stores a bounded forest, not an arbitrary graph. A root has no parent. Every child has exactly one parent, a derived depth, and the root ID copied from the validated lineage. A child delegate cannot equal any ancestor issuer or delegate, which prevents authority identities from cycling back into the tree.

Each `MandateRecord` stores the declared packet, the effective packet, issuer, delegate, parent/root IDs, depth, state, child list, action count, and a canonical SHA-256 scope fingerprint. Each `ActionAssessmentRecord` stores the exact action packet, all structural comparisons, stored/effective status, and fingerprints that commit to the mandate and full lineage.

The active states are only `ACTIVE` and `REVOKED`. The graph has no synthetic expiry state.

## Delegation path

`delegate_mandate` performs these steps in order:

1. Validate identifiers, uniqueness, capacity, parent existence, caller identity, active lineage, and depth.
2. Normalize the child packet with exact keys and bounded fields.
3. Build the effective child packet by unioning inherited forbidden actions and carrying parent constraints forward.
4. Check the effective child spending limit and forbidden/allowed overlap against every ancestor deterministically.
5. Run one consensus-backed structural comparison containing every ancestor.
6. Register the child only if every projection is complete and contained.

Checking only the direct parent would allow an intermediate mandate to re-expand a scope that the root had narrowed. All-ancestor comparison closes that gap.

## Action path

`assess_action` is an explicit write because semantic evaluation is nondeterministic. It requires the effective delegate and active lineage, checks the amount against every ancestor, then evaluates the exact action packet against every ancestor. The final status is derived as:

```text
all contained and complete -> AUTHORIZED
complete conflict -> DENIED
otherwise -> UNRESOLVED
```

An amount over any ancestor ceiling is deterministically stored as `DENIED` with reason `SPENDING_LIMIT_EXCEEDED`. Unauthorized callers, malformed packets, duplicate IDs, and inactive lineages revert instead of creating an assessment.

## Revocation path

Revocation changes only the selected record. A view recomputes effective activity by walking the lineage, so root revocation disables every descendant while middle-node revocation disables only its subtree. This avoids an unbounded descendant mutation while retaining effective propagation.

## Consensus projection

The prompt labels evaluator instructions as `POLICY_BEGIN/END` and supplied mandate/action values as `UNTRUSTED_DATA_BEGIN/END`. The evaluator can report only exact structural keys. The validator independently repeats the same prompt and canonical comparison. The contract rejects a child on malformed/disagreeing semantic data and never accepts a model-provided `authorized` field.

