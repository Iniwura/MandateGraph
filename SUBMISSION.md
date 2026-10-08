# MandateGraph submission

## Project

- Name: MandateGraph
- Repository: https://github.com/Iniwura/MandateGraph
- Contract: `contracts/mandate_graph.py`
- Network target: Studio Dev, chain 61997
- Frontend: none

Verified deployment: `0x18950B3F7ed8456557906eC0DE3854897aDEBFAb` ([Studio Dev explorer](https://explorer-studio.genlayer.com/address/0x18950B3F7ed8456557906eC0DE3854897aDEBFAb)); transaction `0xfe293f7a894e2e3918728e879f2399ae5a7740bedd3de778a9f1d5cae20213cb`; status `ACCEPTED`, execution `FINISHED_WITH_RETURN`.

## Core claim

MandateGraph is a semantic delegation firewall. It prevents permission laundering by requiring each child mandate and each assessed action to be contained in every ancestor authority, not only the direct parent.

## Packet and rules

The packet fields are `purpose`, `allowed_actions`, `resource_scope`, `spending_limit`, `recipient_scope`, `location_scope`, `forbidden_actions`, and `special_constraints`. Numeric limits are integer ceilings checked deterministically. Effective child packets retain inherited forbidden actions and constraints. The root issuer, current delegate, one-parent linkage, maximum depth of six, and bounded storage are enforced by contract code.

Semantic output is a strict projection with no final authorization field. `AUTHORIZED` is derived only when all ancestor comparisons are complete and contained. Model disagreement, malformed output, and unresolved ambiguity cannot authorize.

## Verification

The repository includes 85 adversarial tests covering root validation, access control, transitive containment, gradual widening, inherited prohibitions, graph integrity, bounded storage, revocation propagation, action authorization, consensus disagreement/malformed results, prompt injection, fingerprints, and fail-closed unresolved behavior.

The exact gate commands and pinned runtime are in `README.md`. The checked-in schema is `schema/mandate_graph.json`; the hostile audit is `docs/SECURITY_AUDIT.md`.

The deployed source readback matches the frozen local source exactly: `da4c714104b96eefe74d4d277171dd4c63939bfbf4e2b707191b402e43657f13`.

## Limitation

The contract enforces the registered mandate model but cannot prove that an external agent obeys it. Downstream systems must require a successful assessment before executing a real-world action.

