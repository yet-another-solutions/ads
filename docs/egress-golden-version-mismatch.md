# Golden-version mismatch on stored pairs

A stored pair is created under one golden identity and the manager is later
upgraded to another. The ledger keeps the golden version captured at pair
creation; the deployed manager carries its own golden inputs. When the two
diverge, every cleanup builder the new manager would assemble differs from the
one the pair was created with.

`pair_cleanup._configuration()` fences this case ("pair cleanup builder
configuration changed") and refuses to proceed. The fence is the correct
fail-safe: no cross-version cleanup, no force-clear, no implicit regeneration.

## Observed instance

Session `dc2ace4e-f771-4de2-9a37-3bc97b0a88ef` was created under golden
v0.0.41 while the manager ran v0.0.48. The fence held, but the recovery pass
recorded the verdict only as a repeated warning and kept minting new
`cleanup_work` rows for the same pair on every pass (11,856 rows before the
pair was wiped manually on 2026-09-30). No product path existed to record the
mismatch, bound the work amplification, or dispose of the stranded pair.

## Open design and implementation work

This case needs a designed product exit, not another manual wipe:

- Detect and durably record a golden-version mismatch when a pair is captured
  or recovered, as retained evidence rather than a repeating warning.
- Bound recovery behavior for mismatched pairs so `cleanup_work` does not
  accumulate unboundedly across passes.
- Provide an explicit operator-facing disposition for a pair stranded by a
  golden upgrade (retirement or retained-state transfer), preserving the
  original invocation as the only settlement authority.
- Review the same fencing for attachment-generation and other manager golden
  inputs that a redeploy can change under stored pairs.

Constraints that must hold in any design: the creator fence and dispatch
admission barriers stay intact, no automatic force-clear or record removal is
introduced, and evidence lines never carry exception, API or SQL bodies.
