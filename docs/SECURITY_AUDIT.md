# Hostile security audit

The audit was performed after the 85-test suite passed and after the contract lint/validation/type gates passed.

1. **Gradual widening:** closed. Every child is compared with every lineage record, and direct numeric ceilings are checked against every ancestor.
2. **Omitted inherited restrictions:** closed. Effective forbidden actions are a case-insensitive union; parent constraints are carried into the effective packet.
3. **Numeric ceiling increase:** closed deterministically before semantic acceptance.
4. **Broad wording hiding expansion:** fail-closed semantic projection requires `WITHIN` for every field; broad or conflicting relations cannot authorize.
5. **Regaining root authority after narrowing:** closed by all-ancestor checks on each new edge.
6. **Revoked branch authorizing:** closed. Every write walks the lineage; views derive `effective_active`; stored authorizations become effectively denied after revocation.
7. **Sibling interference:** absent. Revocation is lineage-local and sibling records are not traversed or mutated.
8. **Authority cycle:** closed by one-parent lineage validation, bounded traversal, and rejecting child delegates equal to any ancestor issuer/delegate.
9. **Caller-controlled lineage fields:** absent. Root ID, depth, and parent/root linkage are derived internally.
10. **Model directly deciding authorization:** absent. The model can return only strict relation facts; code derives delegation acceptance and action status.
11. **Prompt injection erasing a prohibition:** closed by policy/data delimiters, inherited effective packets, exact projection normalization, and prompt-injection regression tests.
12. **Validator disagreement:** fail-closed. Leader and validator canonical projections must match inside `run_nondet`.
13. **Leaf-only action evaluation:** absent. Action comparisons include the entire lineage.
14. **Delegate impersonation:** closed by sender checks against the stored delegate and issuer checks for revocation.
15. **Fingerprint replay:** closed. Action fingerprints bind mandate, delegate, exact action packet, mandate fingerprint, and lineage fingerprint.
16. **Unbounded storage/runtime:** bounded by explicit graph, children, actions, text, list, depth, and numeric limits.
17. **Unresolved accidentally authorizing:** closed. `UNRESOLVED` is never contained, and `_has_conflict` does not turn unresolved data into a denial that could be misread as authorization.

## Residual risk

Natural-language containment remains dependent on the evaluator’s semantic interpretation. The contract therefore exposes `UNRESOLVED` and requires downstream systems to treat anything except an effective `AUTHORIZED` assessment as non-executable. MandateGraph also cannot enforce behavior outside the contract.

