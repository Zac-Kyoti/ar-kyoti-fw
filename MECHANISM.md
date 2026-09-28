# Analog Rytm DIRECT START / DIRECT JUMP / TEMP JUMP — confirmed mechanism

Standalone summary, independent of `NOTES.md`'s session-log narrative. Every claim below
is **measured** (directly observed in Ghidra/radare2 disassembly of the extracted
`section_3_MAIN_OS.bin`, MAIN OS 1.73, load base `0x40000400`) unless marked **inferred**.
See `NOTES.md` Sessions 1–7 for the full derivation trail and raw evidence; this document
states only the conclusion, for direct comparison against OT's own DIRECT JUMP code.

> **2026-09-27:** the OT port is done. V6.4 reproduced this mechanism exactly on the OT
> (hardware-confirmed); V7 shipped with one deliberate change — the landing position comes
> from an absolute clock counter instead of the outgoing pattern's master step, which is
> where AR's own shifts come from (`AR_DJ_QUIRKS.md`). The invariant below held: V7 is still
> a total, synchronous rebuild on one tick; only its input changed.

## Scope

PTN CHG (pattern change) on the Analog Rytm has four modes, persisted as a small integer
at a fixed offset (`+0x74`) on the PTN CHG picker's own UI storage object:

| value | name       |
|-------|------------|
| 0     | SEQUENTIAL |
| 1     | DIRECT START |
| 2     | DIRECT JUMP |
| 3+    | TEMP JUMP (saturates to 2 at the read site below — see "TEMP JUMP" below) |

This document covers DIRECT START and DIRECT JUMP in full; TEMP JUMP only insofar as it
is indistinguishable from DIRECT JUMP at the layer traced here. SEQUENTIAL does not use
any of this mechanism — see "SEQUENTIAL is a separate pathway" below.

## The pipeline, in commit order

### 1. Mode read

`FUN_400b3d1e(picker_object + 0x74)` reads the persisted mode value. Called from exactly
two places: the UI dispatcher (below) and `FUN_4003e636` itself (a near-certain re-read of
the same value, nothing rewrites the field in between).

### 2. Conditional dispatch — SEQUENTIAL is filtered out before any of the rest runs

The UI event dispatcher (`FUN_4003fc14`, a large multi-feature per-event dispatch loop)
detects a PTN-CHG request, stashes the requested pattern index, and reads the mode:

```
mode = FUN_400b3d1e(picker+0x74)
if mode == 0 (SEQUENTIAL):
    skip FUN_4003e636 entirely
else:
    FUN_4003e636(picker, requested_pattern_index)
```

`FUN_4003e636` — and everything below it in this pipeline — is **never reached** for
SEQUENTIAL. SEQUENTIAL instead falls through to a generic, PTN-CHG-unaware "picker value
changed" notify pathway shared by other UI fields on the same object; that pathway's
eventual write target was not traced (out of scope — SEQUENTIAL doesn't need the
atomic-commit invariant this document is about, since it has no early-application option
to race against).

### 3. Queue write — `FUN_4009a5b0`, called from `FUN_4003e636`

Writes three globals together, freshly, on every request:

- `DAT_405667dc` — the resolved target pattern.
- `DAT_405667e0` — start-position-behavior flag: **non-zero for DIRECT START, zero for
  DIRECT JUMP/TEMP JUMP** (see step 5).
- `DAT_405667e8` — countdown base, recomputed from the *current* tick position, not
  accumulated from a prior request. **This recompute-on-every-request property is what
  makes a second request before the first commits behave correctly** — there is no stale
  countdown left over from a superseded request.

If the transport is stopped (`DAT_405666e0 == 0`), `FUN_4009a5b0` instead calls
`FUN_4009a2ae`, a synchronous immediate setter (see "No-context immediate path" below) —
there is nothing to quantize against, so the countdown/commit machinery is bypassed
entirely rather than degenerating into a zero-length wait.

### 4. Countdown — `FUN_4009905c`, per-tick

Each sequencer tick, this function checks `DAT_405667e4` (a step-resolution-scaled
countdown derived from `DAT_405667e8` and a small lookup table at `0x401a8ff0` — measured
contents `3, 4, 6, 8, 12, 24, 48`, i.e. ticks-per-step values for different step-resolution
settings). **The wait is to the next step/resolution boundary — at most a few dozen
ticks — never a wait for the rest of the currently-playing pattern.** Both DIRECT START
and DIRECT JUMP commit on this same short timescale; they differ only in what happens to
the step position at the moment of commit (step 5).

### 5. Atomic commit

At the countdown boundary, `FUN_4009905c` writes:

```
DAT_40566754 = DAT_40566755 = DAT_405667dc
```

**Both globals are written together, in the same two instructions.** There is no window
where the "current pattern" pointer and its paired slot disagree, and no separate
apply-now code path elsewhere that could write one without the other. Immediately after
this commit, in the same function:

```
if DAT_405667e0 != 0:                       # DIRECT START
    new_step = 0                            # restart
else:                                        # DIRECT JUMP / TEMP JUMP
    step_len = new_pattern.record[0x14eb3]  # per-pattern step-length field
    new_step = (step_len < 1) ? old_tick_counter : (old_tick_counter mod step_len)
```

This is the DIRECT START vs DIRECT JUMP distinction, mechanically confirmed at this exact
site: DIRECT START always resumes at step 0; DIRECT JUMP/TEMP JUMP keep timeline position,
wrapped (modulo) into the new pattern's own length.

`new_step` is **one master scalar**. It is not the end of the commit — see step 6, which
Session 7 missed entirely and which is the part that matters for the OT port.

### 6. Per-track state rebuild — the real payload of the commit

AR has **13 tracks** (12 drum + 1 FX), each with an independent sequence length and step
resolution. Per-track sequencer state lives in a set of **parallel 13-entry byte arrays**.
The commit does not preserve, adjust, or repair them. It **recomputes every one of them
from scratch**, from the single master `new_step` plus each track's own length, in one
unconditional 13-iteration loop at `0x4009927c`–`0x400992d2`:

```
A6 = 0x40566720   A5 = 0x4056673a   A4 = 0x4056672d   A3 = 0x405667ba   A2 = 0x40566830
A1 = pattern record base ; D1 = 0
loop:                                        ; 13 iterations
    D3 = D5 ? *(A1 + 0x2c5)                  ; per-track scale mode -> THIS track's length
            : *(A0 + 0x14eb3)                ; else pattern-wide length (word)
    D7 = D0                                  ; D0 = master new_step, reloaded every pass
    D2 = D7 mod D3                           ; divsl.l D3,D2:D7  -- remainder
    A1 += 0x395                              ; next track record
    *(A6)++ = D2                             ; per-track STEP
    *(A5)++ = D2 - 1
    *(A4)++ = 0
    *(A3)++ = -1
    *(A2)++ = D2
until ++D1 == 13
```

A second loop just before it (`0x400991de`–`0x40099202`, same 13×`0x395` walk) rebuilds the
per-track countdown-reload array from each track's own resolution index:

```
*(0x405667c7 + t) = ticksPerStep[ *(track_t + 0x2c7) ] - 1
```

Complete inventory of per-track arrays written by one commit — **all 13 entries each,
tiling contiguously, every boundary independently confirmed by the code's own `cmpa.l`
sentinels** (`0x40566720`, `0x40566747`, `0x40566782`, `0x405667d4`):

| array | width | value written |
|-------|-------|---------------|
| `0x405666ec` | long | `1` |
| `0x40566720` | byte | `new_step mod trackLen` |
| `0x4056672d` | byte | `0` |
| `0x4056673a` | byte | `(new_step mod trackLen) - 1` |
| `0x40566775` | byte | per-track resolution index (or the pattern-wide one) |
| `0x405667ba` | byte | `-1` |
| `0x405667c7` | byte | `ticksPerStep[trackRes] - 1` |
| `0x40566830` | byte | `new_step mod trackLen` |

Plus master scalars: `0x405666e4 = new_step` (word), `0x405666e8 = new_step - 1`,
`0x405666e6` = master ticks-per-step − 1, `0x40566774` = master resolution index,
`0x405667d4 = -1` (word), and the paired pattern write of step 5.

Per-pattern fields used: `0x14eb3` pattern-wide length (word), `0x14eb9` **per-track scale
mode flag**, `0x14eba` pattern-wide resolution index. Per-track record fields: `+0x2c5`
length (byte), `+0x2c7` resolution index (byte). Track stride `0x395` (917); the loop bound
`0x2e91` = exactly 13 × `0x395`. Pattern record stride `0x14f00`, base `0x40b6a620`.

`0x14eb9` is the direct analogue of OT's `SCALE_MODE` (pattern `+0x8e55`): **AR has OT's
per-track scale complexity too.** AR's correctness therefore is not a consequence of a
simpler data model — it is a consequence of *how* it commits.

The same rebuild discipline appears at a second, independently-timed commit site
(`0x40099370` onward, gated on `0x405667d6` and `0x40566748 == 1`), which reconstructs
`0x405667c7[t]` with byte-identical logic (`0x400993e8`–`0x40099404`). Two separate commit
paths, one shared rule: *rewrite the whole per-track vector, never patch it.*

**Methodology note:** Ghidra's printed operand order for ColdFire `divsl.l` is unreliable
(it renders `4c412800` and `4c437802` with `D2` first in both, though `D2` is the
quotient/dividend in one and the remainder in the other). Read the extension word:
field(14:12) = dividend **and** quotient destination, field(2:0) = remainder. Both sites
above were settled this way and cross-checked against which register holds the dividend on
entry — same family of hazard as objdump garbling `mvs`/`mvz`/`divsl` into `.short`.

## TEMP JUMP

`FUN_400b3d1e`'s mode read **saturates any value ≥ 3 to 2**. TEMP JUMP is therefore
byte-for-byte indistinguishable from DIRECT JUMP through this entire pipeline — same
queue call (`FUN_4009a5b0(pattern, 0)`), same keep-position commit behavior. Its
distinguishing "reverts afterward" behavior must live in separate bookkeeping not located
by this document (**inferred**, plausibly reusing the already-known `DAT_40566756`
"previous pattern" slot to snap back later — not yet checked).

## No-context immediate path — `FUN_4009a2ae`

A synchronous, unconditional "set pattern now" primitive, distinct from the queued
mechanism above: writes `DAT_40566754` directly, resets step position, re-runs song/chain
bookkeeping and per-pattern note/tempo overrides, and notifies — no countdown, no
`DAT_405667dc`/`e0`/`e8` involvement. Called only when there is no running playback
position to quantize against (transport stopped, or `FUN_4003e636`'s own no-mode default
branch). Not mode-specific; not part of the DIRECT JUMP invariant itself.

## SEQUENTIAL is a separate pathway

SEQUENTIAL is filtered out at step 2 before any of the atomic-commit machinery is reached.
Its own commit mechanism (however it defers the change until the current pattern's natural
end) has not been located and is believed to be structurally unrelated to the countdown/
atomic-write pipeline described here (see `NOTES.md` Session 7 for the evidence that rules
out the earlier, wrong guess that it shared a queue write with the DIRECT path).

## The candidate invariant, stated for comparison against OT

Three properties. The third was found only after step 6 above was traced, and it is the one
that explains OT's stalled effort.

0. **Total per-track state rebuild, not repair.** Every per-track sequencer variable is
   recomputed from scratch at commit, from one master `new_step` and each track's own
   length/resolution, in a single unconditional loop over all 13 tracks. No per-track value
   survives a commit; nothing is adjusted in place; there is no dependence on accumulated
   history, and therefore no such thing as a "stale" per-track variable. OT's effort has
   instead been *repairing* individual per-track globals one at a time as each staleness
   revealed itself (`STEP_IN_PAT[t]`, `TRK_SCALE_IX[t]`, `CNTDN_TBL`, `REFILL_TBL`,
   `BAR_CTR`, table-arm cadence) — six fixes, each exposing the next. AR shows the whole
   category is avoidable.

Supporting the above:

1. **Atomic paired write**: the current-pattern pointer and its paired/pending slot are
   written together, in the same two instructions, with no window where one lags the
   other and no second code path that could apply a change without going through this
   same write.
2. **Fresh-per-request countdown recompute**: the countdown that gates the commit is
   recomputed from the current tick position on *every* incoming request, not accumulated
   or reused from a previous one — so a second DIRECT JUMP request issued before the first
   one commits cannot leave stale timing state behind.

Both are properties of a single function (`FUN_4009905c`, plus the queue-side recompute in
`FUN_4009a5b0`) with a single, short (step-resolution-scaled) countdown — not a
full-pattern wait, and not split across multiple independently-timed code paths.
