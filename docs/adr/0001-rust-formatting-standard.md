# ADR 0001 — Rust formatting standard for cjp2p-rust

- **Status:** Proposed (tooling in this change; node-side items await kermit)
- **Author:** Zach Norman <zach@nor.mn>
- **Deciders:** Zach Norman, Christopher Pearson (kermit4)
- **Affects:** `src/` (node), `cjp2p-ctl/` (control tool crate), `Makefile`, CI

## Context

An earlier assumption that kermit's node code was hand-formatted and *not*
rustfmt-reproducible (458–603 lines of churn) **was wrong** — those measurements
omitted kermit's actual rustfmt options, so rustfmt was reformatting inside his
macros (where all his long lines live). With his real config the node is
`cargo fmt`-clean.

### kermit's config (from his Makefile)

```
cargo fmt -- --config skip_macro_invocations='["*"]' --config match_arm_blocks=false
```

- `skip_macro_invocations=["*"]` — never reformat inside macros. His words:
  *"logic rarely exists inside those, just text/formatting … intentionally not
  readable."* His long lines are macro bodies, deliberately compact.
- `match_arm_blocks=false`; `max_width` unset → default 100 ("400 sounds big").

Both options are **nightly-only** (unstable). On stable they don't apply: the
`rustfmt.toml` form warns and ignores them; the `--config` CLI form exits 0
**without writing the file** — so kermit's existing `make pretty` silently
no-ops on a stable toolchain. Reproducing his format requires `cargo +nightly fmt`.

### Shared philosophy (the authors agree)

kermit: *"Multiline is more readable."* He only compacts macro bodies (non-logic
output text). Zach prefers multiline for logic too. Agreed principle: **multiline
for logic; leave macro bodies alone.** The single divergence is
`use_small_heuristics`: Zach sets `Off` (expand); kermit keeps the default.

### What caused the original churn

A global `PostToolUse` hook ran bare **stable** `rustfmt` on every `.rs` edit —
no config, no macro-skip — multi-lining kermit's macros (~583-line noise). The
node was never the problem; the tooling was.

## Decision

**Per-crate `rustfmt.toml` on a shared nightly base, differing only in one knob;
the Makefile is the single source of truth for the format command.**

1. **`cjp2p-ctl/` (Zach's)** — crate-local `rustfmt.toml`:
   ```
   unstable_features = true
   max_width = 100
   use_small_heuristics = "Off"     # Zach's divergence: multiline
   skip_macro_invocations = ["*"]   # kermit's, adopted
   match_arm_blocks = false         # kermit's, adopted
   ```

2. **The node (`src/`)** keeps kermit's config. *Proposed:* a repo-root
   `rustfmt.toml` encoding it, so the node is reproducibly clean. *kermit's call.*

3. **Tooling — implemented in this change.** The rustfmt invocation lives once,
   in the Makefile (`FMT_FLAGS`); editors, the Claude hook, and CI all call these
   targets rather than duplicating it:
   - `make pretty` — `cargo +nightly fmt` (fixes the silent stable no-op).
   - `make pretty-check` — `cargo +nightly fmt --check`; run by
     `.github/workflows/fmt.yml` on push/PR (the enforcement backstop).
   - `make pretty-file FILE=…` — format one file; for editor format-on-save and
     a *personal* (uncommitted) Claude `PostToolUse` hook.

   Per kermit's habit, review with `git diff -w` so whitespace never obscures logic.

## Options considered

- **A. One repo-wide config.** Erases Zach's `use_small_heuristics=Off`.
- **B. Per-crate configs on a shared nightly base (chosen).** Each crate owns its
  one divergence; macro/match knobs shared. Lowest friction.
- **C. Stable only.** Rejected — kermit's options are nightly-only.

## Consequences

- ✅ Node reproducibly fmt-clean (once root `rustfmt.toml` lands); `make pretty`
  actually applies now; CI enforces it.
- ✅ Zach keeps multiline; both share the macro/match conventions.
- ⚠️ Formatting requires the **nightly** toolchain (CI installs it).

## Open questions for kermit

1. OK to add a repo-root `rustfmt.toml` encoding your Makefile config?
2. OK with a crate-local `rustfmt.toml` in `cjp2p-ctl/` differing only by
   `use_small_heuristics = "Off"` (your code untouched)?
3. Pin nightly via `rust-toolchain.toml`, or keep formatting a Makefile/CI step
   so day-to-day builds stay on stable?
