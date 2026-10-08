# MandateGraph portal brief

## What it is

MandateGraph is a compact authority primitive for agents that need to delegate bounded natural-language work without silently widening the original grant. It models issuer → delegate mandates as a rooted, depth-limited forest and applies the invariant `CHILD_AUTHORITY ⊆ EVERY_ANCESTOR_AUTHORITY`.

## Example

An owner can create an active root for Agent A:

```text
Arrange Paris business travel; transport and lodging only; max 2000;
gift cards forbidden.
```

Agent A can issue Agent B a narrower lodging mandate with max 800. A request by Agent B to issue “general trip spending” with max 1500 fails both the immediate numeric ceiling and the inherited prohibition model. A structured “book a Paris hotel” action for 650 can be assessed and stored as `AUTHORIZED` when every semantic comparison is complete and contained.

## Why GenLayer

The contract uses GenLayer consensus for the part that is genuinely semantic: whether bounded purpose, action, resource, recipient, location, and constraint descriptions are contained. It uses ordinary deterministic contract logic for identity, ancestry, numbers, storage bounds, fingerprints, status derivation, and revocation. This separation keeps the model from becoming the authority source.

## Why it matters

Direct-parent-only checks are insufficient. An intermediate delegate can appear narrower than its parent while quietly recovering authority forbidden by the root. MandateGraph compares against the complete bounded lineage on every delegation and action assessment, and it carries inherited forbidden actions forward in stored effective packets.

## Safety posture

The contract has no expiry fiction, no unbounded graph, and no free-form model reasoning in consensus state. It fails closed on unresolved semantic containment. The system is still an enforcement primitive: an external booking, treasury, or agent runtime must require the on-chain assessment before acting.

## Verified Studio Dev deployment

- Chain: Studio Dev, chain 61997
- Contract: `0x18950B3F7ed8456557906eC0DE3854897aDEBFAb`
- Deployment transaction: `0xfe293f7a894e2e3918728e879f2399ae5a7740bedd3de778a9f1d5cae20213cb`
- Consensus/execution: `ACCEPTED` / `FINISHED_WITH_RETURN`
- Explorer: https://explorer-studio.genlayer.com/address/0x18950B3F7ed8456557906eC0DE3854897aDEBFAb
- Frozen source SHA-256: `da4c714104b96eefe74d4d277171dd4c63939bfbf4e2b707191b402e43657f13`
- Deployed source readback: exact SHA match

The live smoke used `live-mg-root` and `live-mg-child`: the valid child was accepted, the broadening child was rejected before registration, the 650-unit Paris hotel action was authorized, and root revocation made the descendant inactive and the stored authorization effectively denied.

