# Design Notes

These notes document the package's security and lifecycle contracts that are easy to miss if you only read the
quick-start material or skim the test suite.

Each note is intentionally short and follows the same structure:

- `Purpose`
- `Invariants`
- `Success Path`
- `Failure / Edge Cases`
- `Implementation Anchors`
- `Authoritative Tests`
- `Change Triggers`

The current note set is:

- `guard-lifecycle-and-events.md`: standard Laravel auth events plus the package contextual events, and the exact
  successful event order for `attempt()`, direct `login()`, bearer auth, and refresh.
- `refresh-rotation-and-replay.md`: why refresh is stateful, how per-device rotation works, and when the package uses
  `rotation_mismatch` versus `rotation_reuse`.
- `fail-closed-pid-did.md`: why `pid` and `did` are treated as commitments rather than advisory hints.
- `access-only-mode.md`: the supported bearer-only, no-devices migration path.

These documents are secondary to the code and tests, not a replacement for them. If a note and a cited test disagree,
the test should be treated as authoritative until the mismatch is resolved.
