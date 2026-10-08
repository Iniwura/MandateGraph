# MandateGraph

MandateGraph is a standalone GenLayer Intelligent Contract implementing a semantic delegation firewall. An issuer grants a bounded mandate to a delegate; the delegate may issue a child mandate only when the child remains contained in every ancestor mandate. This prevents gradual permission laundering through a delegation chain.

There is no frontend, token, marketplace, voting layer, or reputation system. The repository contains the contract, its adversarial harness, the generated public schema, and deployment/submission documentation.

## Security invariant

For every accepted edge in the rooted forest:

```text
CHILD_AUTHORITY ⊆ EVERY_ANCESTOR_AUTHORITY
```

The contract walks the bounded lineage from root to the proposed parent. Numeric ceilings and inherited prohibitions are checked deterministically. Natural-language containment is evaluated once per operation as a strict structural projection, with GenLayer leader/validator agreement. The contract derives the final result; the model never returns a final authorization decision.

## Mandate packet

Every root and child packet has exactly these fields:

```json
{
  "purpose": "Arrange business travel to Paris",
  "allowed_actions": ["book transportation", "book lodging"],
  "resource_scope": "travel budget",
  "spending_limit": 2000,
  "recipient_scope": "travel service providers",
  "location_scope": "Paris, France",
  "forbidden_actions": ["purchase gift cards"],
  "special_constraints": "single business trip"
}
```

`spending_limit` is an integer application unit. It is checked against every ancestor without asking the model to compare numbers. A child effective packet unions inherited `forbidden_actions` and carries forward the parent constraints. Omitting an inherited restriction never removes it.

All text, list counts, list item lengths, identifiers, graph depth, children, mandates, and action assessments are bounded. The current bounds are `MAX_DEPTH=6`, `MAX_MANDATES=128`, `MAX_CHILDREN=8`, `MAX_ACTIONS_PER_MANDATE=32`, eight items per list, 160 characters per list item, 512 characters per text field, and `MAX_SPENDING_LIMIT=10**12`.

## Public API

Writes:

- `create_root_mandate(mandate_id, delegate, mandate_packet)` — caller becomes the issuer.
- `delegate_mandate(parent_mandate_id, child_mandate_id, child_delegate, child_packet)` — only the current parent delegate can issue a child.
- `revoke_mandate(mandate_id)` — direct issuer or root issuer revokes a stored node.
- `assess_action(mandate_id, action_id, action_packet)` — stores `AUTHORIZED`, `DENIED`, or `UNRESOLVED` after checking the action against all ancestors.

Views:

- `get_mandate`, `get_action_assessment`
- `get_ancestry`, `get_child_ids`
- `is_effectively_active`
- `get_mandate_fingerprint`, `get_action_fingerprint`

The action packet has exactly `action`, `target`, `resource`, `amount`, `purpose`, `location`, and `constraints`. Every action assessment fingerprint binds the action ID, mandate, delegate, packet, mandate fingerprint, and lineage fingerprint.

## Revocation

Revocation is stored on the selected node. Descendants are not mutated: `effective_active` walks the bounded ancestry and is false if any ancestor is revoked. A revoked branch cannot delegate or assess a new action. A previously stored authorization is exposed as effectively `DENIED` after its lineage becomes inactive; the original stored result remains available for auditability. Sibling branches are unaffected.

There is intentionally no expiry or wall-clock rule. The contract does not invent time semantics that the deployed runtime cannot enforce reliably.

## GenLayer role and fail-closed behavior

For delegation and action assessment, the leader and validator independently evaluate the same prompt. The prompt separates policy instructions from untrusted mandate/action data and requests only field-level relations: `WITHIN`, `EXPANDS`, `CONFLICTS`, or `UNRESOLVED`, plus a boolean forbidden-action conflict and a semantic status. Extra keys, missing keys, invalid enums, prompt-injection text, disagreement, and malformed output become unresolved; unresolved semantic containment cannot authorize a child or action.

The model is an evaluator of natural-language relationships, not a generic LLM judge. Deterministic code derives acceptance and final action status from the structural projection.

## Limits and non-goals

MandateGraph enforces authority according to its registered structured semantic model. It does not prove that an external agent actually obeys a mandate unless the downstream execution system requires a successful on-chain assessment. Natural-language equivalence depends on the GenLayer evaluator and can be `UNRESOLVED`. The contract does not move funds, execute travel bookings, verify external documents, or guarantee real-world outcomes.

## Reproduce the gates

The proven environment used for this repository is Python 3.12.3 with the pinned packages in `requirements.txt` and `GENVM_VERSION=vstudio-dev`.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pytest -q
GENVM_VERSION=vstudio-dev genvm-lint check contracts/mandate_graph.py
GENVM_VERSION=vstudio-dev genvm-lint typecheck contracts/mandate_graph.py
pyright
GENVM_VERSION=vstudio-dev genvm-lint schema --json contracts/mandate_graph.py
git diff --check
```

The checked-in schema is [schema/mandate_graph.json](schema/mandate_graph.json). The hostile-audit record is [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md). Deployment and portal material are in [PORTAL.md](PORTAL.md) and [SUBMISSION.md](SUBMISSION.md).

