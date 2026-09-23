# Mutation Testing Playbook (gremlins)

This playbook documents a repeatable process for using
[go-gremlins/gremlins](https://github.com/go-gremlins/gremlins) to find real
test gaps in a package and close them with targeted, mutation-proven tests.
It is meant to be followed by any agent asked to "run mutation testing on X
and fix what it finds." Ported from a sibling Go repo (gonzbd) that
originated this process; the resource-safety lessons below were paid for
there and apply to any repo running gremlins, not just that one.

> **Why mutation testing, not just coverage:** coverage tells you a line
> *executed* during tests. Mutation testing tells you whether a test would
> *notice* if that line's logic were wrong. A `LIVED` mutant means the
> mutated code ran and every test still passed — the assertion that would
> catch that bug doesn't exist. `NOT COVERED` usually means the line never
> executed at all during any test — but read it as "no coverage block records
> this expression", which is not always the same claim. See §2b: a `switch`
> case expression has no block of its own, so it reports `NOT COVERED` even
> while tests exercise and kill it.

## 1. Run gremlins

**Always use the wrapper script — never call `gremlins unleash` directly.**

```bash
./scripts/run_gremlins.sh ./<package>
```

e.g. `./scripts/run_gremlins.sh ./par2`, `./scripts/run_gremlins.sh ./rs`,
`./scripts/run_gremlins.sh ./gf16`.

`scripts/run_gremlins.sh` exists because a bare `gremlins unleash` copies the
whole working directory into each worker's isolated build dir without
respecting `.gitignore`. If that scratch space lives anywhere inside the repo
tree, each worker's copy recursively sweeps up scratch data from prior
workers/runs, nesting many levels deep — this produced 168–394GB of disk
usage from a *single* run on gonzbd, independent of worker count, and
coincided with kernel OOM kills. The script fixes this by relocating scratch
space outside the repo (default `~/.cache/par2engine-gremlins`, wiped before
each run) and adds real resource limits: a hard memory cap enforced via a
`systemd --user` cgroup scope (so an OOM kills only this run's own processes,
not arbitrary processes across the machine) and a background watchdog that
stops the run if the scratch dir's disk usage or the wall-clock time exceeds
a cap. Requires `systemd-run` (`systemctl --user status` to check); it
refuses to run without it rather than silently falling back to an unconfined
invocation.

Tunables, all optional (see the script's header comment for the full list):
`GREMLINS_WORKERS` (auto-detected based on CPU/RAM, clamped 4–16),
`GREMLINS_MEMORY_MAX` (auto-detected to 80% of system RAM, fallback `32G`),
`GREMLINS_DISK_MAX_MB` (default `51200` = 50GiB), `GREMLINS_TIMEOUT_SECS`
(default `1800` = 30min), `GREMLINS_DIR` (scratch dir base — must not be
inside the repo, the script errors out if it is).

Mutant-type selection is configured project-wide in `.gremlins.yaml` at the
repo root and needs no flags.

**`timeout-coefficient` is not so simple.** `.gremlins.yaml` sets `100`, and
on a package whose suite is fast (this repo's are — `go test ./par2/...`
runs in well under a second) that value makes essentially every mutant
report `TIMED OUT` — a run that reads like total collapse but is purely an
artifact of the setting. Measured on gonzbd's `internal/nntp`, same tree,
same commit:

| Invocation | Result |
|---|---|
| `--timeout-coefficient=40` (three runs) | 92.1% / 91.7% / 93.2% efficacy |
| config default `100`, workers auto | Killed 0, **Timed out 179**, efficacy 0% |
| config default `100`, `GREMLINS_WORKERS=1` | Killed 1, **Timed out 178**, efficacy 0% |

Worker count is not the variable — the coefficient is. So **pass
`--timeout-coefficient=40` explicitly** on packages with fast suites, and
treat a run that is almost entirely `TIMED OUT` as a configuration symptom to
retry, never as a test-quality result. The direction is counter-intuitive (a
larger coefficient producing more timeouts) and has not been traced to a
cause in gremlins; it is recorded here as an observation, not an
explanation.

Extra `gremlins unleash` flags can be passed through as additional
arguments: `./scripts/run_gremlins.sh ./par2 --timeout-coefficient=40 --dry-run`.

The summary line looks like:
```
Killed: 139, Lived: 59, Not covered: 46
Timed out: 0, Not viable: 0, Skipped: 0
Test efficacy: 70.20%
Mutator coverage: 81.15%
```

- **NEVER run `gremlins` on the entire repository** (e.g. `./...`). Doing so
  will trigger parallel builds and mutant execution across every package at
  once, which rapidly consumes disk space even with the wrapper script's
  protections. Always scope it to a single focused package (`./par2`, `./rs`,
  `./gf16`, `./cmd/gopar`).
- If a run is killed by the memory cap or watchdog, the script prints
  `error: gremlins run was OOM-killed or stopped by the watchdog ...` or
  `error: gremlins run was stopped by the disk/timeout watchdog ...` — retry
  with a lower `GREMLINS_WORKERS` (for OOM) or a higher
  `GREMLINS_DISK_MAX_MB`/`GREMLINS_TIMEOUT_SECS` (for a genuinely large
  package that needs more room, not a runaway).

### Large or slow packages need `nohup` + polling, not a bare foreground run

A run scoped to a large package can still take longer than a single tool
call's timeout. Use:

```bash
nohup ./scripts/run_gremlins.sh ./par2 --timeout-coefficient=40 \
  > /tmp/gremlins-par2.log 2>&1 &
echo "PID: $!"
```

then poll (`while kill -0 <PID> 2>/dev/null; do sleep 10; done`) or check
back later, rather than waiting on it in the foreground. Even the
backgrounded run can be interrupted by an *outer* timeout (e.g. an agent
harness's own long-running-command limit) before the whole package finishes
— that's fine. `gremlins` writes results incrementally, so a log truncated
mid-run (look for `Shutting down gracefully...` at the tail instead of the
final `Killed: N, Lived: N, ...` summary line) still contains real
`KILLED`/`LIVED`/`NOT COVERED` verdicts for every mutant it reached before
the cutoff. Grep the partial log for the specific line numbers your diff
touched (`grep -n "decoder.go:<line>:" gremlins-par2.log`) — if those lines
were reached, the partial run is sufficient proof for the mutation gate on
your change; you don't need a from-scratch complete run just to get the
summary footer.

### Known limitation: `--diff` is broken when scoped to a package

gremlins v0.6.0 has a confirmed upstream bug
([go-gremlins/gremlins#278](https://github.com/go-gremlins/gremlins/issues/278)):
`--diff <ref>` combined with any package/subdirectory argument — including
`cd`-ing into the package directory and omitting the path entirely — reports
every mutant in the changed file as `SKIPPED` (0 killed / 0 lived / 0
not-covered), regardless of what the diff actually contains. This was
verified directly on gonzbd's tree: a real, unambiguous single-line diff
produced `Skipped: 25` with `--diff`, but `Killed: 16, Lived: 0, Not covered:
8` on the same package without it.

Root cause per the upstream report: gremlins compares the diff's file paths
(repo-root-relative, from `git diff --merge-base`) against the AST walk's
paths (relative to the package `CallingDir`), and they only match when
`CallingDir` is `.` — which only happens at the module root, where whole-
module runs are the exact scenario the `NEVER run gremlins on the entire
repository` rule above forbids. There is no scoped invocation that gets a
working `--diff` here.

**Until upstream fixes this, do not use `--diff` for the mutation gate.**
Instead:
1. Run gremlins scoped to the changed package with no `--diff` flag, exactly
   as in step 1 above, to get real `Killed`/`Lived`/`Not covered` numbers.
2. Get the touched line ranges for your change: `git diff main -- par2/<file>.go`.
3. Cross-reference: for each `LIVED`/`NOT COVERED` mutant, check whether its
   line number falls inside a range your diff touched. Only mutants on
   *your* changed lines are the mutation-testing proof obligation for this
   change — pre-existing `LIVED`/`NOT COVERED` lines outside the diff are a
   separate, already-tracked gap (see "2. Triage" below for optionally
   closing those too, if you have time).

This is slower and more manual than `--diff` would be, but it's the only
reliable signal until the upstream bug is fixed.

## 2. Triage: separate signal from noise

Grep the output for `LIVED` and `NOT COVERED` and read each one in source
context (`awk 'NR==<line>{print}' <file>`). Sort them into:

### a. Equivalent mutants — ignore these
A mutation that cannot change observable behavior. The classic example:
`make([]string, 0, 6+len(extraFiles))` — `ARITHMETIC_BASE` mutating the
**capacity** hint. Capacity doesn't affect correctness (slices still grow via
`append`), so no test could ever kill it. Don't write tests for these; note
them and move on.

### b. Coverage-model artifacts — verify before believing `NOT COVERED`
Go's cover tool instruments *blocks*, and a `switch { case cond: }` case
expression is not one — only the case body is. A mutation of the condition
therefore reports `NOT COVERED` even when tests execute it and would kill it.
The `if cond { }` form of the same logic reports normally.

This is not hypothetical: a gonzbd run reported `NOT COVERED
CONDITIONALS_NEGATION` on a `case got != want:` arm of a response-identity
check that was in fact the single most-tested line in that change. Two
independent checks refuted it: the coverage profile had a block with a
non-zero count over that line, and applying the mutation by hand (`!=` →
`==`) failed ten tests.

So before writing a test for a `NOT COVERED` line, confirm it is really
untested:

```bash
go test -count=1 -coverprofile=/tmp/c.out ./<package>/
grep '<file>.go:<line>' /tmp/c.out    # trailing 0 = genuinely unexecuted
```

If the profile disagrees with gremlins, apply the mutation by hand and run
the suite. Writing a test to satisfy a mutant that existing tests already
kill adds a redundant test and — worse — records a false conclusion about
where the gaps are.

### c. Real gaps — group by theme, not by line
Cluster the remaining `LIVED`/`NOT COVERED` lines by what *behavior* they
represent, not by file. On this codebase, likely themes given the hotspot
map (`par2/decoder.go` is the highest-churn, lowest-health file):

1. **A whole optimization path with zero coverage** — e.g. an early-exit
   scan condition with every comparison operator flippable without a test
   noticing. This is the highest-value class of finding: a documented,
   spec-cited, performance-relevant code path that no test exercises
   end-to-end.
2. **Boundary conditions on length/threshold checks** — the classic
   off-by-one blind spot: tests exercise "valid" and "very invalid" inputs
   but never the exact threshold value (packet/body length validation is a
   likely candidate in `par2/packet.go`).
3. **Entire fallback branches never executed** — e.g. relocation/matching
   phases where existing tests call the *helper functions* directly with
   hand-built structs, but never drive the orchestrating function through a
   scenario that actually reaches those phases' internal loops.
4. **Side-effect/logging wiring** — callback invocation and formatting
   helpers, where no test asserts on the callback content or formatted
   output.

**Prioritize #1 and #3** (whole-path / whole-phase gaps on hot or
spec-referenced code) over #2 and #4 — they represent bigger blind spots and
their fixes generalize better.

## 3. Write the test — match the existing fixture style

Before writing anything, read the package's existing test helpers in
`*_test.go`. Mutation-gap tests should look like the tests around them, not
introduce a new style.

**For boundary conditions:** write the exact "one below" / "exactly at"
pair. E.g. `parseFileDescBody(make([]byte, 55))` → nil, `(56)` → non-nil with
empty filename, `(57+)` → non-nil with filename. Two or three cases bracketing
the literal in the `if` condition kill the `CONDITIONALS_BOUNDARY` and
`CONDITIONALS_NEGATION` mutants on that line.

**For whole-path gaps that depend on real thresholds (e.g. file size):**
build the actual fixture at the real scale rather than refactoring the
threshold into an injectable parameter. An 11 MiB temp file write takes
~20ms and proves the *actual* code path, not a parameterized stand-in. Pair
it with a "below threshold" sibling case so the assertion brackets the
condition from both sides — that's what makes the test fail (not just pass)
when the comparison operator is flipped.

**For uncovered fallback phases:** drive the public orchestrator
end-to-end with a fixture engineered so *only* the target phase can succeed
— arrange inputs so every earlier-checked condition misses and only the
phase under test can match.

Add a one-line guard against the (vanishingly unlikely but real) case where
your synthetic content's checksum happens to collide with a sentinel value
— that would silently defeat a `> 0`-style filter and test the wrong path:
```go
if actualCRC == 0 {
    t.Fatal("test content CRC32 is zero — pick different content")
}
```

## 4. Prove the test with manual mutation (red-green discipline)

Applying the same red-green proof used for bug-fix tests to a
*coverage-gap* test (where there's no "fix" to revert) means manually
mutating the targeted condition, confirming the new test goes red for the
right reason, then reverting:

```bash
# Example: prove a boundary test catches a >= → > flip
sed -i 's/seen >= expected/seen > expected/' par2/decoder.go
go test ./par2/ -run TestNewBoundaryTest -v
git checkout par2/decoder.go
```

A test that passes against both the original *and* the mutated code is
testing nothing — fix the test, not the code, if that happens. Do this for
every new test before moving on; it's the only way to know you killed the
mutant you intended to, rather than getting lucky with an unrelated
assertion.

## 5. Run the full quality gate suite

```bash
go vet ./<package>/...
go test -race ./<package>/...
golangci-lint run ./<package>/...
```

Note: `gf16`'s `TestScalarKernelsZeroAllocOnTheTablePath` and related
`ZeroAlloc` tests must be run separately, without `-race` (see the project
CLAUDE.md) — the race detector's own instrumentation allocates.

**Check for *new* lint findings, not just a clean run.** Compare the
before/after issue counts — lint your branch, then lint the merge base
(`git worktree add` a scratch checkout of it, never `git stash` if the stash
stack might be shared with other in-flight work) — so you don't get blocked
by pre-existing debt you didn't introduce, but also don't add to it
gratuitously.

## 6. Re-run gremlins to measure the delta

```bash
./scripts/run_gremlins.sh ./<package> --timeout-coefficient=40 2>&1 | tail -10
```

Compare `Killed`/`Lived`/`Not covered` and `Test efficacy` against the
baseline. Then grep for the *specific* lines you targeted to confirm they
flipped from `LIVED`/`NOT COVERED` to `KILLED`:

```bash
./scripts/run_gremlins.sh ./<package> --timeout-coefficient=40 2>&1 \
  | grep -E "decoder.go:(139|159|167|196|197|221|239):"
```

Some mutants may show `TIMED OUT` on a re-run under load — that's run-to-run
timing variance, not a regression; don't chase it.

It's normal for a few `CONDITIONALS_BOUNDARY` mutants to remain `LIVED` after
a focused pass (e.g. exact-zero-vs-positive distinctions, which require
increasingly elaborate fixtures for diminishing returns). Note them and stop
— chasing 100% mutation score on a package is not the goal; closing the
*real, themed* gaps from step 2 is.

## 7. Commit with the before/after numbers in the body

Conventional commit, `test(<package>):` scope, body states *why* (which
mutation-testing-revealed gap this closes) and the measured score delta —
quantitative claims must be measured, not estimated:

```
test(par2): guard decoder boundary conditions and fallback matching

Gremlins mutation testing flagged a cluster of LIVED/NOT-COVERED mutants in
[theme], code paths whose boundary conditions and fallback branches no test
exercised end-to-end.

[... what was added and why it proves the gap is closed ...]

Mutation score for par2 improves from X% to Y% (A→B killed, C→D lived).
```

## Quick checklist

- [ ] `./scripts/run_gremlins.sh ./<package> --timeout-coefficient=40` (background)
- [ ] Triage `LIVED`/`NOT COVERED`: mark equivalents, verify coverage-model
      artifacts (§2b) before trusting `NOT COVERED`, group real gaps by theme
- [ ] Prioritize whole-path/whole-phase gaps over single-line boundary nits
- [ ] Write tests matching existing fixture style; bracket boundaries on both sides
- [ ] Manually mutate each targeted line, confirm red, revert, confirm green
- [ ] `go vet` / `go test -race` / `golangci-lint` — diff issue counts vs. baseline
- [ ] Re-run gremlins, confirm targeted lines flipped to `KILLED`, record delta
- [ ] Commit with measured before/after mutation score in the body
