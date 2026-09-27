# RE Log — Analog Rytm

Chronological record. Confidence markers: **measured** (directly observed in the binary/
disassembly/tool output) vs **inferred** (reasoned from measured evidence, not yet proven).
Anything wrong gets an explicit retraction, not a silent edit.

> Sibling project: `~/Documents/octatrack-kyoti-fw` ("OT Kyoti FW"). This is a separate
> repo/history by design (see its CLAUDE.md hard-constraints style, copied in spirit not
> content). Read there for RE methodology and hard-learned lessons; do not merge histories.

## Session 1 (2026-09-19)

### Goal

Find the Analog Rytm's own instant/in-time pattern-switch mechanism, to understand what
invariants make it *correct* — the OT project's three independent ColdFire-register fixes
for its own "DIRECT JUMP" feature were each dynamically proven exact in emulation and none
of them fixed the real-hardware symptom across five flashes. See the OT NOTES.md "Session
70" passes 4–15 for the full history of that dead end.

### Setup

- `git init` in `~/Documents/ar-kyoti-fw`, identity set to
  `273702472+Zac-Kyoti@users.noreply.github.com` / `Zac-Kyoti` — **verify
  `git config user.email` before every commit, no exceptions** (the OT project had to
  scrub a real identity from its history after one accidental commit).
- Source firmware: `downloads/Analog-Rytm_OS1.73.syx` (1,631,008 bytes, provided).

### Step 1 — container + device identity  [MEASURED]

`refs/../elektron-firmware-tool` (built from the OT project's `refs/elektron-firmware-tool`,
C tool, no project-specific code — reused as-is per the task's own instruction to check
whether it applies unmodified) on the `.syx`:

```
device                : 00 20 3C / 0x07 (Analog Rytm)      <- DEV_ANALOG_RYTM, not _II
bin container (ELE2)  : build/model 0173, version 1.73
sections               : id=3 MAIN OS  dst=0x40000400  -> 2,824,228 B  checksum OK
```

**The device byte (0x07) is the ORIGINAL Analog Rytm ("MKI"), not the Mk II (0x0c,
`DEV_ANALOG_RYTM_II`).** This is a direct field in Elektron's own firmware container, not
an inference — but per the task's own hard-constraint style (mirroring OT CLAUDE.md's
"Hardware = Octatrack MKI only" rule), **still needs the user's explicit sign-off before
anything gets near a real flash.** Nothing here has touched real hardware yet.

Extracted to `out/section_3_MAIN_OS.bin` (gitignored, Elektron copyrighted material).

### Step 1 — architecture identification  [MEASURED, not assumed]

Did NOT assume ColdFire just because the OT is one — per the task brief, verified from
scratch:

- **Entropy** (`tools/entropy.py`): whole-file 6.73 bits/byte, mean 5.49 — real code/data,
  not encrypted (only 2.5% of windows ≥7.5). Near-identical to the OT's own decompressed
  MAIN OS (mean 5.5) — consistent with the same compression/build pipeline.
- **Opcode-signature probing**: `m68k-elf-objdump -m m68k:isa-a:mac -EB` on the raw image
  decodes cleanly from offset 0. Canonical signatures found:
  - `46fc 2700` = `move.w #0x2700,sr` at file+0x1c — classic m68k/ColdFire supervisor-mode
    boot instruction.
  - `4e7b 0002` = `movec %d0,%cacr` at file+0xce — ColdFire-specific cache-control-register
    write, a near-universal ColdFire crt0/boot fingerprint.
  - MBAR-style on-chip peripheral addresses `0xfc050014`, `0xfc080000` in the first 0x50
    bytes — same address-space shape as the OT's own `0xfc04xxxx`/`0xfc0axxxx` MBAR finds.
  - **Zero illegal-opcode fallbacks** across the first 64,286 decoded instructions
    (200 KB) as `m68k:isa-a:mac` big-endian.
  - Ruled out a false lead: the string `CORTEX` appears in the binary, but context shows
    it's mid-alphabet filler in a dictionary word list (`…CORNER CORRAL CORTEX COTTER…`),
    not an ARM Cortex reference. No other ARM/MIPS/SuperH signature found anywhere.
  - **Conclusion: ColdFire / m68k, big-endian — same ISA family as the OT.**
- **Load base** (`tools/find_base.py`, pointer↔string correlation, same method as OT's
  `tools/find_base.py`): unambiguous peak at **`0x40000400`** (10,995 strings resolve via a
  direct pointer, next candidate only 4,930) — **identical base address to the OT's own
  build**. Strong circumstantial evidence for a shared internal platform/toolchain
  (consistent with the OT project's own "DPS-1 = internal Elektron platform, shared across
  ColdFire machines" note — no literal `DPS-1` banner string found yet in this image,
  unlike the OT's `ElektronOctatrack DPS-1 0002` banner; **inferred**, not proven, that this
  later-generation build simply dropped/moved that banner).
- Artifacts: `out/entropy.csv`, `out/pointers_to_strings.csv` (12,090 rows), `out/strings.txt`.

**Toolchain note [inferred, strong]:** the binary carries thousands of C++ mangled/typeinfo
strings (`St15_Sp_counted_ptrI...`, `N10AnalogRytm...`, class names like `Pattern`,
`PatternSettings`, `SequencerStates`). This is a materially more C++-OOP, RTTI-carrying
codebase than what OT's own notes describe finding in 1.40C — expected, since 1.73 is a
much later build (AR MKI's later firmware generations moved to a heavier internal
framework: `Value`/`ValueWithMirror`/`*Storage_v*_t`/`*ChangedInfo` data-binding classes).

### Step 2 — Ghidra project  [DONE]

- `ghidra_project/armax.gpr` (gitignored, independent of the OT's own `ghidra_project/`).
- Ghidra 12.1.2 (same version OT uses), language **`68000:BE:32:Coldfire`**, loaded as raw
  binary at base `0x40000400` via `analyzeHeadless -loader BinaryLoader
  -loader-baseAddr 0x40000400`.
- **Gotcha (matches OT's own note "Ghidra 12 doesn't ship Jython → use Java")**: this
  install has no PyGhidra either — `.py` postScripts fail with `Ghidra was not started with
  PyGhidra. Python is not available`. All Ghidra scripts here are Java (`GhidraScript`
  subclasses), same as OT's `tools/ghidra/*.java`.
- `tools/ghidra/GhidraImport.java`: reads `out/pointers_to_strings.csv`, defines 161
  strings, labels all 12,090, defines 12,090 pointer xref sites. Ran clean.
- `tools/ghidra/GhidraFindDirectJump.java`: xref-search + decompile helper (see next).
- **JDK note**: `analyzeHeadless` needs `JAVA_HOME` set explicitly —
  `export JAVA_HOME=/opt/homebrew/opt/openjdk@21` (brew's `ghidra` formula depends on it but
  doesn't put it on `PATH`).

### Step 3 — found the feature, by its own literal name  [MEASURED]

In `out/strings.txt`, immediately after the `PatternSelectionView` string-pool marker:

```
PTN: SEQUENTIAL
PTN: DIRECT START
PTN: DIRECT JUMP
PTN: TEMP JUMP
```

**Elektron's own AR firmware calls the feature "DIRECT JUMP" verbatim** — this is not a
name the OT project coined; it is literally what the string says here, in a menu class
(`PatternSelectionView`) that also owns `COPY PATTERN`/`PASTE PATTERN`/`CLEAR PATTERN`.
Confirmed this is a real contiguous 4-entry pointer array, not coincidence:

```
0x4019af64 -> "PTN: SEQUENTIAL "
0x4019af68 -> "PTN: DIRECT START"
0x4019af6c -> "PTN: DIRECT JUMP"
0x4019af70 -> "PTN: TEMP JUMP"
```
(`out/pointers_to_strings.csv` rows 2700–2703; four consecutive 4-byte slots — a plain
`const char* names[4]` table for a 4-valued enum.)

**Only one xref to the table base**, at `0x400407f6`, inside `FUN_4003fc14` (entry point
`0x4003fc14`) — a very large function (spans well past `0x40040800`, several KB). Ghidra's
ColdFire decompiler badly mis-lifts it (same documented limitation as OT: "Cannot properly
adjust input varnodes" on complex-frame ColdFire functions) — the pseudo-C it emits has
bogus stack-variable aliasing and is **not to be trusted verbatim**. Went to raw
disassembly instead:

```asm
0x400407ec  pea.l   0x10                  ; 0x10 = 16 = 4 entries * 4 bytes -- the WHOLE table
0x400407f0  move.l  #0xb6db6db7, d4       ; a reciprocal-multiply constant (unrelated? unclear)
0x400407f6  pea.l   0x4019af64            ; push the table base
0x400407fc  lea.l   -0x20(a6), a3
0x40040800  move.l  a3, -(a7)             ; push a3 (a local/frame buffer)
0x40040802  jsr     0x40096b6c            ; call(a3, table=0x4019af64, count_bytes=0x10)
```

**Inferred**: `FUN_40096b6c(dest, table, size)` is a generic "populate a picker/menu from a
fixed string array" helper — the args (dest buffer, table pointer, exact byte-size of the
whole table) match that shape more than a single-entry formatter. This is consistent with
`FUN_4003fc14` being `PatternSelectionView`'s UI event handler and this specific branch
being "user is cycling the PTN CHG option in a picker" — i.e. **this is the UI code that
shows the 4 option names, not the code that decides sequencer behavior.**

Confirmed `FUN_4003fc14` is a UI event dispatcher, not sequencer logic: the small helper
functions it calls dozens of times with different bit positions (`FUN_400706f0`,
`FUN_4007072c`, `FUN_400706fc`, `FUN_4007070c`, `FUN_40070698`…) are all trivial one-liners
of the shape `return event_arg->field_0x10 >> N & 1` (a flags-bitfield test) or
`return event_arg->field_0xc` (the event/message-type code) — a classic C++ UI event-object
accessor family, not sequencer state. The huge `if/else` structure keyed on that type field
(cases `0x40`..`0x82` seen so far) is a per-message-type dispatch inside one view's
`handleEvent`-style method.

**Not yet found — the actual target for step 3/4 of this project:**
- The persistent field that stores a pattern's PTN CHG mode. Strong candidate storage
  structs, from RTTI strings: `AnalogRytm::patternStorage_v5_t` or
  `AnalogRytm::patternSettingsStorage_v1_t` (both have a matching
  `Pattern::updateMirror` / `PatternSettings::updateMirror` binding class). No field-name
  strings survive (RTTI only preserves class/method names, not private members) — locating
  the actual byte offset needs structural tracing, not string search.
- The sequencer-side code that *reads* that field when a pattern switch is actually
  requested/committed, and decides SEQUENTIAL (wait for end) vs DIRECT START (restart now)
  vs DIRECT JUMP (switch now, keep position) vs TEMP JUMP (temporary switch that reverts).
  **This is the piece that matters most** — it's the AR's analogue of the OT's own
  `FUN_400a1eea` sequencer tick engine, and finding *how it stays correct* is the whole
  point of this project.
- One promising unexplored lead: `SequencerStates` (`StaticSingletonI15SequencerStatesE` —
  a global singleton), found via string search. Likely owns current/next-pattern playhead
  state and is a strong candidate for where a pattern-switch commit would live.
- **Checked and it's a dead end**: xrefs to the `PatternSettings::updateMirror` /
  `Pattern::updateMirror` RTTI strings (`0x400a8a9a`, `0x400a8b50`) land in real code, not
  static data — but that code turned out to be **C++ static-initialization / type
  registration** (building a `type_info`-shaped object with the mangled name at program
  startup: `pea.l <name-string>; jsr FUN_40033100` right after what looks like an
  `operator new` call), not the methods themselves or anything that runs at pattern-switch
  time. The actual `Pattern::updateMirror`/`PatternSettings::updateMirror` function bodies
  are at different, not-yet-found addresses — string-xref search finds their *registration*,
  not their *code*.

### Confirmed NOT pursued (per task scope)

- No DSP/audio-path investigation — this is believed to be pure ColdFire/sequencer-side,
  matching the OT project's own hard-won framing (an LED-only OT test already proved its
  own version of this bug is visible at the CPU/UI level with zero audio involved, and a
  DSP tangent was correctly redirected away from twice in that project's history).
- No OT firmware patches written yet, and none should be until step 3 (AR mechanism, not
  just its name) is actually understood — the "build DIRECT JUMP from scratch in the OT"
  idea remains explicitly shelved per the task brief.

### Extended Session 1 — ruling out the easy hypotheses  [MEASURED, negative results]

Two follow-up checks, both negative but worth recording so a future session doesn't
re-walk them:

1. **Not a Ghidra-recognized jump table.** Ghidra's own auto-analysis (`Create Address
   Tables`, already run) tagged 27 `switchdataD_*` jump tables and dozens of `caseD_*`
   labels in the image (`tools/ghidra/GhidraListSwitches.java`). Cross-referenced every
   function `FUN_4003fc14` (the picker-owning dispatcher) calls
   (`tools/ghidra/GhidraCallees.java`, 66 unique callees) against every function
   containing a recognized switch table — **zero overlap**. So the PTN CHG mode is not
   dispatched via a compiler-generated jump table anywhere directly reachable from the UI
   handler. (Doesn't rule out an if/else compare-chain, which GCC also uses for small
   switches and which Ghidra doesn't label the same way — just rules out *this specific,
   mechanically-searchable* pattern.)

2. **Retracted a bad read.** In the extended session, misread `FUN_40137440` (called from
   `FUN_4003fc14` with `*(param_1+0x80)`, compared against 2 in the earlier decompile
   excerpt) as a plausible "get current picker value" getter. Raw disassembly shows it's
   actually a **bit-counting loop** (shift-and-accumulate over 4 bytes, `lsr.l`/`add.l` in
   a 4-iteration loop) — a generic popcount/bit-tally utility, most likely counting set
   bits in a per-track enable bitmask (`param_1+0x80` reads like a 16-track bitmask
   elsewhere in the same function, e.g. `*(uint*)(param_1+0x80) & (1<<n)` patterns).
   **Unrelated to PTN CHG. Retracted** — flagging this explicitly rather than silently
   dropping it, per this project's own discipline (and exactly the kind of
   decompiler-trusting mistake the OT project's Session 70 passes got burned by).

**Honest state of play**: `FUN_4003fc14` is confirmed to be a large (3764-byte), multi-
feature `PatternSelectionView` event dispatcher handling several unrelated UI concerns
(PTN CHG picker, per-track bitmask toggling, bank/pattern copy-paste, at least one other
picker) behind one message-type-keyed dispatch. Its Ghidra decompilation is unreliable
(known ColdFire limitation) and its raw disassembly is dense enough that continuing to
manually re-derive semantics instruction-by-instruction has a real misreading risk — seen
firsthand in the FUN_40137440 retraction above. **Further progress on where the mode is
*stored* and, especially, where the sequencer *acts* on it needs a different, more
structural approach than "keep reading FUN_4003fc14 top to bottom."**

### Extended Session 1, continued — found the SequencerStates constructor  [MEASURED]

Followed the one string xref to `"SequencerStates"` (`0x4003535e`, referenced from
`0x4003535c`) to its containing function at **`0x40035350`** — and this one is not another
static-init dead end. Raw disassembly confirms it's the real
**`SequencerStates::SequencerStates()` constructor**:

```asm
0x4003538a  move.l  0x4019a134, (a2)      ; vtable ptr -> object+0x00
0x40035394  move.l  0x4019a154, d1
0x4003539a  move.l  d1, 0x3c(a2)          ; vtable ptr -> object+0x3c
0x4003539e  move.l  0x4019a144, d0
0x400353a6  move.l  d0, 0x18(a2)          ; vtable ptr -> object+0x18
0x400353aa  move.l  0x4019a164, d0
0x400353b0  move.l  d0, 0x40(a2)          ; vtable ptr -> object+0x40
0x400353b4  lea.l   0x48(a2), a0          ; then zero/init a region starting at +0x48
0x400353bc  addi.l  0x7c, d0              ; ... spanning at least another 0x7c bytes
```

**Inferred**: four distinct vtable pointers at four different offsets in one object,
sourced from four consecutive 0x10-byte-spaced vtable slots (`0x4019a134/44/54/64`) — the
classic C++ multiple-inheritance layout (this class implements several interfaces, each
contributing its own vtable at its own base-subobject offset). Object size is at least
`0x48 + 0x7c = 0xc4` (196) bytes based on the zero-init span, likely more.

Also present in the same constructor: a call to `FUN_400343bc(a2, 0, d2, 0x64)` — a
size-0x64 (100-byte) sub-allocation/init, shape matches a generic "register this singleton
by name" utility (name string ptr `d2` = the same `"SequencerStates"` string) rather than
being part of the class's own sequencer-state fields.

**Not yet done**: identify what the 4 vtables' virtual methods actually are (would need
each `0x4019a1xx` table's entries individually decompiled), and what the plain-data fields
past `0x48` hold. This is real progress on "class layout" but the pattern-switch consuming
code itself is still not located — that requires either finding `SequencerStates`'
non-virtual accessor methods (probably called via a `getInstance()`-style function
elsewhere, not yet located) or finding its virtual methods via the 4 vtables above.

### Where this session leaves off

Two full passes in, the concrete state is: **the feature's UI-facing identity is solid
(measured)**; **the runtime mechanism is not yet found**, but three dead ends are now
ruled out and documented (jump-table dispatch, `FUN_40137440` misread, RTTI-string-xref-as-
shortcut-to-method-bodies) plus one real structural foothold gained (`SequencerStates`'
constructor and partial object layout). This is consistent with the task brief's own
framing that this rivals the OT project's multi-session RE scale — no reason yet to expect
this resolves faster. The `NEXT` list below is deliberately the most concrete, checkable
starting point for whoever (or whichever session) picks this up next.

## Session 2 (2026-09-19, continued)

Picked up exactly where Session 1 left off: `SequencerStates`' 4 vtables, then a pivot back
toward the PTN CHG code once that lead's limits became clear.

### SequencerStates' 4 vtables are destructor-only  [MEASURED — dead end, recorded]

Dumped all 4 vtable-groups the constructor wires up (`0x4019a134/44/54/64`, standard
Itanium-ABI layout: `{offset_to_top, rtti_ptr}` header immediately before each 2-slot
table). All **8 slots total resolve to compiler-generated destructor thunks** — this-
pointer-adjusting stubs (`moveq #N,d0; add.l d0,4(a7); jmp/bra <shared-impl>`) that all
funnel into one shared implementation at `0x40156d6e` (itself just re-stamps 4 vtable
pointers into the object — the classic "reset vptrs to base-class state" pattern inside a
C++ base-object destructor) plus one deleting-destructor variant at `0x40156dc0` that also
calls `operator delete` (`0x40080e60`). **No application logic here.** `SequencerStates`
apparently exposes no other virtual methods through these 4 interfaces — it's most likely
a mostly-POD state holder that also implements several tag/mixin interfaces (for safe
polymorphic deletion) but does its real work through plain non-virtual member functions or
free functions instead. Not pursuing this class further without a more specific reason to
come back to it.

### The actual PTN CHG cycling call site, isolated  [MEASURED, high confidence]

Went back to the raw disassembly right after the table-population call
(`0x40040802 jsr 0x40096b6c`, confirmed — see below — to be a plain `memcpy`) and traced
the next few instructions:

```asm
0x40040808  pea.l   0x1                 ; param_2 = 1
0x4004080c  move.l  0x74(a2), -(a7)     ; param_1 = PatternSelectionView+0x74 (a "current
                                        ;   pattern"-ish accessor -- read-only in this
                                        ;   function, so set up elsewhere, e.g. the view's
                                        ;   own constructor, not yet found)
0x40040810  jsr     0x400b3db2.l
```

**`FUN_40096b6c` decompiles cleanly (small function) and is a plain byte-copy `memcpy`**
(`dest, src, n` — 16/4/1-byte chunked copy loop). Confirms it copies the whole 16-byte,
4-pointer PTN CHG table into a local buffer for the picker widget — nothing selection-
specific happens here, exactly as inferred (not yet confirmed) in Session 1.

**`FUN_400b3db2` also decompiles cleanly**:
```c
undefined4 FUN_400b3db2(int *param_1, int param_2) {
  iVar1 = (**(code **)(*param_1 + 0x28))(param_1);   // vcall slot 0x28: "get current item"
  if (iVar1 == 0) return 0;
  iVar1 = (**(code **)(*param_1 + 0x28))(param_1);
  iVar2 = (**(code **)(*param_1 + 0x28))(param_1);
  uVar4 = *(int *)(iVar2 + 0x30) + param_2;           // read field+0x30, add delta (=1 here)
  uVar4 = (uVar4 < 0) ? 2 : ((uVar4 < 3) ? uVar4 : 0); // clamp/wrap
  *(uint *)(iVar1 + 0x30) = uVar4;                     // write back
  (**(code **)(*param_1 + 0x10))(param_1, 0);          // vcall slot 0x10: "commit/notify"
  iVar1 = (**(code **)(*param_1 + 0x28))(param_1);
  return *(undefined4 *)(iVar1 + 0x30);                // read back, return
}
```
This is a **"get current value, add a delta, wrap, write back, notify, re-read" helper** —
exactly the shape of an encoder-driven enum cycler, operating polymorphically through a
`param_1` accessor object (vcall slot 0x28 = get-current-item, slot 0x10 = commit/notify)
onto a value field at `item + 0x30`.

**Cross-checked via xref search (`tools/ghidra/GhidraXrefsTo.java`): `FUN_400b3db2` has
exactly ONE caller in the entire 2.8 MB image — this exact call site.** It is not a shared
generic utility; whatever it does, it does only for this one code path.

**Open question, flagged rather than glossed over**: the wrap clamp keeps values in
`{0, 1, 2}` (three states, wrapping `uVar4<0 → 2`, `uVar4≥3 → 0`), but PTN CHG has **four**
named modes (SEQUENTIAL/DIRECT START/DIRECT JUMP/TEMP JUMP). Two explanations, neither
confirmed: (a) this specific call — made with a hardcoded `param_2=1` right after building
the picker — seeds/validates a *different*, 3-valued field on the same shared "current
pattern" accessor (not PTN CHG's own mode), with the real PTN CHG value read/written by a
sibling call elsewhere in the same case block not yet located; or (b) the 4th mode (TEMP
JUMP) is handled out-of-band from this particular cycle (e.g. as a momentary/held state
rather than a persisted cycle position) and the true persisted enum really is 3-valued at
this storage layer. **Do not treat this as solved — it's the strongest lead so far, not a
confirmed answer.**

**Methodology note, logged so it isn't repeated**: an early re-scan of this function for
other `0x74(a2)` uses initially over-collected, because `r2`'s `pd <N>` takes an
**instruction count, not a byte count** — passing Ghidra's byte-length (3764) as the `pd`
argument disassembled roughly 2–3× past the function's real end (`0x40040ac7`) and pulled
in unrelated code from the next function (which turned out to be doing real object
construction — vtable store to `(a2)` — i.e. *not* part of `FUN_4003fc14` at all). Caught
by checking the result against Ghidra's own reported function body range before drawing
conclusions from it. Re-filtered to the real bounds: exactly 3 reads of `+0x74` inside
`FUN_4003fc14`, no writes (it's set up elsewhere); only one of the three reads is in the
PTN CHG block, the other two are in unrelated cases (one confirmed to be the case-`0x82`
handler, which clears an unrelated flag field `+0xc5`).

### NEXT (for the next session)

1. **Find `PatternSelectionView`'s own constructor** (same vtable-store technique used to
   find `SequencerStates::SequencerStates()` in Session 1: look for a function that does
   `move.l #<vtable-addr>, (this)` where the vtable's own slots eventually lead back into
   this same dispatcher / class's other methods). This resolves what `+0x74` actually is
   and, via its class's vtable slot 0x28, what class implements "get current item" —
   likely `Pattern` or a small wrapper around it. That in turn tells us definitively
   whether `item+0x30` is really the PTN CHG mode field.
2. If `+0x74`'s class turns out to be `Pattern` (or wraps it) and `+0x30` is confirmed as
   the PTN CHG mode storage: search the whole binary for **other** readers of that same
   struct offset (same technique as the `FUN_400b3db2`/`0x74(a2)` cross-check) — the
   sequencer-side reader, wherever it is, must also compute `pattern_ptr + 0x30` (or reach
   it through the same vtable slot 0x28) to actually act on the mode at switch-commit time.
3. Resolve the 3-vs-4-value open question above before treating any of this as the answer.
4. Do not start on OT adaptation (task step 4) before step 3 is solid — still true, still
   not there yet.

## Session 3 (2026-09-19, continued) — mapped the Project/Pattern/PatternSettings data
   architecture; PTN CHG's exact storage byte still not pinned down

Followed the constructor trail from `PatternSelectionView` all the way down through the
project's real C++ data model. This is the deepest, most load-bearing structural mapping
done so far — recorded in full because it's expensive to re-derive and several early
hypotheses in this chain were wrong and had to be corrected mid-trace (a couple of those
corrections are as valuable as the parts that panned out).

### Retraction: Session 2's "strongest lead" was a false trail  [MEASURED — corrected]

Session 2 ended treating `FUN_400b3db2` (called once, from right next to the PTN CHG
table-population code, cycling a value via a vtable-slot-0x28/field+0x30 pattern) as the
strongest candidate for the mode-cycling logic. Traced it all the way down and **it isn't
PTN CHG at all**:

- `PatternSelectionView::PatternSelectionView()` is at **`0x4003efc6`** (found via the
  `"PatternSelectionView"` string's *code* xref at `0x4003efd6` — unlike `Pattern`'s RTTI
  xrefs in Session 1, this one really is the constructor, confirmed by a `move.l
  #<vtable>, (a2)` vtable install at `0x4003f02e`).
- Its `+0x74`/`+0x78` fields (the ones `FUN_400b3db2` operates on, reached via `+0x74`) are
  initialized from a **global 252 KB singleton**, obtained via `FUN_401556cc()` — a
  classic lazy-singleton getter (`if (cache==0) { allocate 0x3d61c bytes; construct; cache
  it; } return cache;`), same shape as the `SequencerStates` singleton getter found
  earlier. This singleton's constructor (`FUN_400af438`) references the string
  `LOAD_PROJECT` — **this is the entire in-RAM Project object**, not anything
  PatternSelectionView-specific.
- Two tiny one-line helpers turn out to be plain field-offset adjustors:
  `FUN_400ab6ce(p) { return p + 0x30; }` and `FUN_400ab706(p) { return p + 0xe8; }`.
  `PatternSelectionView+0x74 = Project + 0x30`.
- **`Project + 0x30`'s constructor is `FUN_400b4f50`, and it is labeled `SOUND_SETTINGS`**
  (`FUN_401721f4(..., s_SOUND_SETTINGS + 6)`, same construction-helper shape used
  everywhere in this codebase to tag a sub-object with its project-file key name).

**Conclusion: `FUN_400b3db2` cycles a field inside the project's global sound-output
settings, not a per-pattern PTN CHG mode.** It's very likely incidental — something else
on the same UI screen gets refreshed when entering the PTN CHG picker, and this is that
unrelated refresh, not the feature we're after. Retracting it as a lead. Recorded here so
nobody re-walks this exact chain expecting a different answer.

### The real Project layout, mapped from its constructor  [MEASURED]

`FUN_400af438` (`Project`'s constructor, `param_1` = 32-bit-word-indexed in the pseudocode
below — multiply by 4 for the byte offset) builds a large, flat, straight-line object graph
— this is genuinely the master in-RAM project blob:

| word offset | byte offset | sub-object ctor | tag string | notes |
|---|---|---|---|---|
| `+0xc` | `+0x30` | `FUN_400b4f50` | `SOUND_SETTINGS` | confirmed unrelated to PTN CHG |
| `+0x1d` | `+0x74` | `FUN_400b37b0` | — | not yet examined |
| `+0x3a` | `+0xe8` | `FUN_400a4af0` | — | not yet examined |
| `+0x54e` | `+0x1538` | `FUN_400a8ed0` | (same ctor as the Pattern array below — odd, needs a second look) | |
| `+0x6be..` | | `FUN_400b88b2` × loop to `0x2200`/`0x44` = **128** elements, 0x44 B stride | — | not yet examined |
| **`+0xf53`** | **`+0x3d4c`** | **`FUN_400a8ed0`, looped to `0x2de00`/`0x5bc` = exactly 128 elements, 1468 B (`0x5bc`) stride** | **`s_Pattern`** | **confirmed: this is `Pattern patterns[128]`** (128 = 8 banks × 16 patterns, matches the AR's known pattern count) |
| `+0xc6d3` | | `FUN_400b88b2` × loop to `0x540`/`0x54` = 16 elements | — | not yet examined (16 = could be per-bank data) |
| `+0xc823` | | `FUN_400bc644` | — | not yet examined |

(The `+0x54e` row using the *same* ctor address as the confirmed Pattern array is odd and
flagged, not explained — worth checking whether that's a real second use or a misread of
the log; not chased further this session.)

### Pattern's own layout, mapped from `Pattern::Pattern()` (`FUN_400a8ed0`)  [MEASURED]

| word offset | byte offset | contents |
|---|---|---|
| `+0` | `+0x00` | vtable ptr |
| `+0xb` | `+0x2c` | **embedded `PatternSettings` sub-object** (`FUN_400a899e`, confirmed via `s_PatternSettings` tag — matches the `Pattern`/`PatternSettings` RTTI pairing found in Session 1) |
| `+0x1c..` | `+0x70..` | 13 × `0x60`-word (`0x180`-byte) blocks via `FUN_400bfcba` — almost certainly per-track pattern data (13 tracks) |
| `+0x154` | `+0x550` | another sub-object, `FUN_400a9cf4` (not yet examined) |
| `+0x165` | `+0x594` | single byte, explicitly zeroed, **immediately followed by 13 bytes set to 1** (`+0x595..+0x5a1`) — reads as a 14-element per-track(+master?) boolean array, not an isolated enum. Considered and set aside as a PTN CHG candidate — shape doesn't fit a 4-valued mode. |

### PatternSettings' vtable, dumped and partly decompiled  [MEASURED]

Vtable at `0x401aaeb0` (16 slots dumped). The two slots matching the generic accessor
pattern seen in Session 2:

```c
// slot 0x28 (word 10) = 0x4016dafc -- "getMirror()"
undefined4 FUN_4016dafc(int this) { return *(undefined4 *)(this + 0x10); }

// slot 0x10 (word 4) = 0x4016e4fa -- "commit/notify(value)"
void FUN_4016e4fa(int *this, undefined4 value) {
  if (*(char *)(this + 9) == '\0' && this[8] != 0)
    (**(code **)(*this + 0x44))(this, this[8], value);   // vcall: notify observers
  FUN_4016e482();
}
```

This confirms the earlier reverse-engineered framework shape (generic `Value`/
`ValueWithMirror<T>` template: `getMirror()` returns a cached pointer at a fixed offset,
`notify()` fans out to observers through yet another vtable slot) — and this exact
`getMirror()` body is almost certainly **shared, identical machine code reused by many
different `ValueWithMirror<T,T>` instantiations** (Pattern, PatternSettings, Kit, etc. all
likely point their own vtable's slot 0x28 at this same 10-byte stub), which is *why*
`FUN_400b3db2` and the real PTN CHG accessor (wherever it is) would look structurally
identical despite operating on totally different storage.

**Chased the mirror-pointer binding one level further and hit a real dead end, corrected
in place rather than left standing**: traced `PatternSettings`' base-class constructor
(`FUN_4016dc82`, the `Value<T>` template base) and confirmed the `+0x10` mirror-pointer
field is initialized to **0 (NULL)** when constructed with no external storage (exactly
Pattern's own case: `FUN_400a899e(pattern+0x2c, 0, 0)`). Guessed that `Pattern`'s next
constructor call, `FUN_40155a6e(pattern+0x2c, pattern)`, was the deferred binding call for
that NULL mirror pointer — **decompiled it and it isn't**: `FUN_40155a6e(int p1, p2) {
*(int*)(p1+4) = p2; FUN_40034340(); }` writes to **word offset 1 (`+4`), not word offset 4
(`+0x10`)** — this sets some other field (most likely a parent/owner back-pointer for the
`Observable` notification chain), not the mirror pointer. **So it's still not known where
(or whether) `PatternSettings`'s own `+0x10` mirror pointer for a `Pattern`-owned instance
actually gets bound.** Flagging rather than guessing further.

### The two remaining Pattern::Pattern() sub-calls, checked  [MEASURED — both ruled out]

- **`Pattern+0x550`'s constructor, `FUN_400a9cf4`, is `PatternParamLocks`** (tag string
  `s_PatternParamLocks`, matches the RTTI class from Session 1). A real, known AR/OT
  feature (per-step parameter locks) — not PTN CHG.
- **The 13-iteration loop's three calls per track are back-reference wiring, not storage
  binding**: `FUN_400bca58` sets track `+0x44` = pointer to the owning `Pattern`;
  `FUN_400bca76` sets track `+0x40` = the track index; `FUN_400bca6a` sets track `+0x2c` =
  pointer to the `PatternParamLocks` sub-object. The per-track object itself (constructor
  `FUN_400bfcba`) is tagged **`s_Active_Track`** — confirms the 13×0x180-byte array is
  `Track tracks[13]`, each with its own `Observable`-based sub-object at `+0x2c` and a
  further `FUN_400a705e(track+0x30, track, 0)` sub-construction at `+0x30` not yet
  examined. None of these three calls touch `PatternSettings` or set anything at offset
  `+0x10` on it.

**So after five separate call sites checked in `Pattern::Pattern()`
(`PatternSettings` itself, the 13 `Track`s' three binder calls each, `PatternParamLocks`),
none of them binds `PatternSettings`'s mirror pointer.** Either it's bound from *outside*
`Pattern::Pattern()` entirely (e.g. a post-construction pass over the whole 128-pattern
array, done once after `Project`'s constructor returns — plausible, since `Project`'s own
constructor had several loops/passes after the main sub-object construction block that
weren't examined in detail), or `PatternSettings`'s `getMirror()` genuinely can return NULL
in some states and something else entirely (not the `getMirror()`/`+0x30` pattern that
misled Session 2) is how its fields actually get touched. Not resolved this session.

## Session 3, continued — traced the picker's full setup block; a real methodology risk
   found and checked (not confirmed to matter, but worth every future session reading)

Picked option 2 from the prior NEXT list: traced forward from the PTN CHG table-population
call (`0x40040802`) through to where that case's code exits.

### Picker construction traced through to its exit  [MEASURED]

Past the table `memcpy` and the (now-known-unrelated) `FUN_400b3db2`/SOUND_SETTINGS call,
the block continues: computes an array element pointer via the same global bounds pair seen
in Session 1/2 (`0x416c5050`/`0x416c5054`), stores a **literal `3`** into a local (plausibly
"max index" for a 4-item, 0-based list — consistent with the PTN CHG table's 4 entries,
*unlike* `FUN_400b3db2`'s 3-valued wrap, which is one more small piece of evidence they're
unrelated), then calls `FUN_40158ff8` (builds some kind of list/picker model object from
that array+bounds) and `FUN_40076d18` (binds it to a cached "current pattern accessor",
loaded earlier into `-0x3c(a6)` from a source not yet traced). The block ends with
`bra.w 0x40040abc`, jumping to a shared exit point — **no explicit "on-confirm write this
value" callback pair was found here**, unlike the case-`0x52` block from Session 2
(`FUN_4003e0d8`/`FUN_4003eee8`). Whatever commits the user's PTN CHG choice is either
folded generically into the list-picker widget itself (`FUN_40158ff8`/`FUN_40076d18`, not
yet examined), or happens somewhere this trace hasn't reached.

### Real methodology risk found, checked, and (for this specific path) ruled out
   [MEASURED]

While tracing backward to pin down the case's true start, found a real, previously
unaccounted-for hazard: at `0x400404cc`, in a **different, nearby case block**, the
compiler reassigns the presumed-stable "this" register: `lea.l 0xac(a2), a2` — from that
point on, `(a2)`-relative reads in *that* block mean `PatternSelectionView + 0xac + offset`,
not `PatternSelectionView + offset`. This is exactly the kind of thing that could silently
invalidate offset attributions made anywhere else in this function by assuming `a2` stays
canonical throughout — a risk not previously considered in Sessions 1–3.

**Checked whether this affects the PTN CHG code specifically**: traced every branch that
lands at `0x400406a8` (where the PTN CHG case's guarded body begins) — both `0x40040080`
(`beq.w`) and `0x40040096` (`bra.w`) — and the entire stretch from `0x40040000` through
`0x400406a8` reads `0x74(a2)`/`0x6c(a2)` consistently with no reassignment in between.
**For this specific path, `a2` is confirmed canonical.** The `0xac` reassignment lives in
an unrelated, disjoint case. Not a retraction — a hazard identified, checked, and cleared
for the region actually relied on so far. **Flagging it anyway for every future session**:
any *new* offset claim made about a region of this function that hasn't been walked
backward to its entry this carefully should be treated as unverified until it has.

### Additional corroboration that `+0x74`/SOUND_SETTINGS is generic, not PTN-CHG-specific
   [MEASURED]

Found a *second*, independent call site with the exact same shape as `FUN_400b3db2`
(`move.l 0x74(a2),-(a7)` + a literal delta + a call to a small helper — here
`FUN_400b3ca6` instead of `FUN_400b3db2`) inside a completely different, earlier case
in the same dispatcher (around `0x40040058`). Two separate, unrelated cases both touching
`+0x74`/SOUND_SETTINGS with the same "get accessor, apply small delta" shape confirms it's
a generic, frequently-reused utility field — not something specific to whichever case
happens to also be building the PTN CHG picker.

### `FUN_40158ff8`/`FUN_40076d18` checked — both generic, no commit logic  [MEASURED]

- `FUN_40158ff8`: allocates a 176-byte (`0xb0`) reference-counted wrapper object
  (`refcount fields = 1,1`, vtable `&PTR_FUN_4019a910`), forwards four of its own
  incoming stack args into `FUN_40074f22`. This is a generic "wrap this array + bounds
  into a ref-counted picker-options object" constructor — no application-specific write
  happens inside it.
- `FUN_40076d18`: guards on `*(this+0x2c)` being non-NULL, then calls
  `FUN_40077af6(*(this+0x2c), &local, param_3)` and does standard ref-count
  increment/decrement/release bookkeeping around it. Also generic dispatch/notify
  plumbing (same shape recurs constantly throughout this codebase's C++ framework),
  not a value setter.

Neither writes anything resembling a PTN CHG mode value. The four stack-passed arguments
`FUN_40158ff8` receives (labeled `in_stack_00000014/18/1c/20` in its decompile, since
they're the caller's pushed values) are the last unexamined piece of this specific trace —
one of them is plausibly a callback pointer for "user confirmed a selection," but
resolving that requires mapping the exact pushes at the call site (`~0x40040846`–
`0x4004088a`) to call-frame slots precisely, which hasn't been done with confidence.

## Session 4 (2026-09-19, continued) — exhausted the picker-construction path; built a
   stack-argument tool; definitive negative result

### Built `tools/ghidra/GhidraStackArgs.java`  [tool, reusable asset]

Directly acting on Session 3's own recommendation: rather than keep hand-computing stack
depth through PEA/MOVE/CLR/SUBQ/ADDQ sequences (error-prone — caught myself making a real
mistake mid-session, see below), wrote a Ghidra script that mechanically walks straight-
line code from a start address to a target `jsr`, tracks every SP-affecting instruction,
and reports each pushed item's callee-relative offset. Verified it against the exact
region that motivated it (`0x40040846`–`0x4004088a`, the call into `FUN_40158ff8`): its
output matched my hand-trace numbers exactly once a mnemonic-matching bug was fixed (Ghidra
returns `"move.l"` not `"move"` from `getMnemonicString()` — trivial but would have silently
under-counted pushes). Confirmed the tool's byte-offset output against
`FUN_40158ff8`'s own decompiled `in_stack_0000NNNN` labels: **matched exactly after
accounting for a consistent 1-byte baseline shift** (Ghidra's own labels start counting
one byte higher than a naive "return-address-at-0" model — not fully explained, but the
*relative spacing* between all four referenced offsets matched the tool's output perfectly,
which is what matters for resolving which pushed item is which).

**Near-miss worth recording**: while first trying to verify this by hand with `objdump`,
mis-converted a virtual address to a file offset (`0x400407EC → 0x407ec`, when it's
actually `0x403ec` — a digit-transposition error) and got a wildly different, unrelated
instruction stream back. Briefly suspected radare2's address mapping was fundamentally
broken (it has been printing an unexplained `"using oba to load the syminfo from different
mapaddress"` warning on every single invocation since Session 1). Cross-checked against
Ghidra's own listing at the *correct* offset and confirmed r2 and Ghidra agree — the
warning is apparently benign for this workflow, and the discrepancy was entirely a self-
inflicted arithmetic error. **Lesson, not yet acted on**: always double-check VA↔file-
offset arithmetic against Ghidra's listing (which is base-aware) before trusting a raw
`objdump -b binary` call, and stop treating r2's `oba` warning as evidence of anything
without a specific reason to.

**Separately confirmed (genuine, minor)**: radare2's plain `m68k` disassembly mode
mis-decodes ColdFire's `muls.l`/`mulu.l` 32×32 instruction (`0x4c04 1800` at
`0x40040830`, shown as `invalid` by r2, correctly `muls.l D4,D1` in both Ghidra's listing
and `m68k-elf-objdump -m m68k:isa-a:mac`) — this is the exact same ColdFire decode
limitation the OT project already documented in its own notes. Didn't feed into any
conclusion drawn before being caught. **Going forward: treat Ghidra's own listing (or
`m68k-elf-objdump -m m68k:isa-a:mac`) as ground truth over r2's plain-m68k disassembly
for any ColdFire 32×32 multiply.**

### Definitive result: the entire PTN CHG picker-construction path is generic UI chrome
   [MEASURED — strong negative result]

Using the new tool, precisely resolved what `FUN_40158ff8` receives from its caller
(4 extra stack args beyond its own `param_1`) and traced every one of them through to its
actual use:

- The computed pointer into the fixed global `0x416c5050`-based array (indexed by
  `FUN_400b3db2`'s SOUND_SETTINGS-derived result × a `muls.l`-computed stride, then
  clamped) → passed all the way down into **`PopupWindow::PopupWindow()`**
  (`FUN_40074c4c`, confirmed via its own `s_PopupWindow` tag string) → stored at
  `PopupWindow + 0x98`.
- Chased that stored field to its one real consumer, `FUN_400748a8` — a **rendering/
  layout function** (pixel-geometry math, calls to what are clearly draw-box/draw-text
  primitives). `PopupWindow+0x98` is read there as `*(*(this+0x98)+4)+4` and passed to a
  text-drawing call — **it's the popup's title-bar string, not a write target.** The
  `0x416c5050` array is a small table of pre-formatted dialog titles (or similar display
  strings), and the SOUND_SETTINGS-derived value just happens to select which cosmetic
  title variant to show — completely unrelated to any pattern data.
- The other three passed args resolved to: a pointer into the just-`memcpy`'d copy of the
  PTN CHG string table (one specific string within it), a constant zero flag byte, and the
  literal `3` (max index for the 4-item list) — all picker-display bookkeeping.
- `FUN_40158ff8` itself: allocates a 176-byte ref-counted wrapper, forwards to
  `FUN_40074f22` → `FUN_40074c4c` (`PopupWindow`'s real constructor). No write anywhere.
- `FUN_40076d18` (called right after, on the newly-created popup): generic guarded
  dispatch/notify with standard ref-count bookkeeping. No write.
- The type-erased closure vtable at `0x4019a910` found earlier: confirmed its slot 2 is a
  double-indirect call thunk (`(**(this+0xc))()`), the standard shape of a `std::function`-
  style invoker — meaning the picker's actual value-changed/confirm handler, if wired
  through this object at all, is a runtime-bound closure whose concrete implementation
  isn't visible via this vtable — it would need to be found at the point the specific
  closure gets *allocated*, which this trace never reached.

**Conclusion**: every single instruction from the PTN CHG string-table population
(`0x400407ec`) through the popup's full construction and title rendering has now been
traced, and **none of it writes a pattern-settings value anywhere.** This is a strong,
well-supported negative result — not "still not found," but "conclusively not in this
code path." Whatever commits the user's PTN CHG selection lives entirely outside the
picker-construction sequence examined across Sessions 2–4.

### Found `PopupWindow`'s confirm signal — but not the write-back  [MEASURED]

Went back into `PopupWindow`'s own vtable (dumped earlier this session, 22 slots at
`0x401a53ac`) looking for something more than layout/rendering code. Found it:

- **`FUN_4007502c` (vtable slot 2) is `PopupWindow`'s generic event handler.** On event
  type `0x45` (from the same `FUN_40070698`/`FUN_4007072c` event-field-accessor family
  seen throughout this codebase since Session 2 — plausibly "OK/SELECT pressed", not yet
  independently confirmed), with two guard bit-tests passing, it calls through **the
  object's own vtable slot `0x2c`** — i.e. `(*this->vtable)[0x2c](this)`.
- **Slot `0x2c` resolves to `FUN_40076cb8`**, which does: if not already confirmed
  (checked via `FUN_40076c94`, a small linear-scan helper), set `*(this+0x30) = 1` — **a
  "confirmed" flag** — and if `*(this+0x2c) != 0` (a stored value, set by a *different*
  function, `FUN_40076ea0`, seen earlier this session doing `*(this+0x2c) = param_2` when
  called), call `FUN_40077744(this)`.
- **`FUN_40077744` turns out to just be `*(this+0x22) = 1`** — a plain flag set (most
  likely "needs redraw"/"dirty"), not a value write. Dead end for finding the commit
  itself, but confirms `+0x30` really is a distinct "user confirmed" signal separate from
  whatever `+0x2c` holds.

**So: pressing OK on this popup sets a "confirmed" flag on the popup object, but nothing
found so far in this trace actually reads back the user's selection and writes it
anywhere.** The likely mechanism, based on this shape (a "confirmed" flag rather than a
synchronous callback firing on button-press): the popup's **owner** polls `+0x30` on a
later pass (its own tick/update, or the next time the same dispatcher runs) and only then
reads the popup's selection and commits it — a common older-style modal-dialog pattern.
That reader is still unlocated.

## Session 5 (2026-09-19, continued) — MAJOR: found the per-tick sequencer engine

Abandoned the UI-construction thread per the strategic pivot flagged above and went
bottom-up instead: decompiled `SequencerStates::SequencerStates()`'s full body (only the
vtable-install prefix had been read before) and found three non-virtual, `SequencerStates`-
specific setup calls at its end (`FUN_400352d4`, `FUN_40035224`, `FUN_40035282`), all
sharing one shape — "query some raw global state, compare against a cached field, update +
notify-on-change if different." Decompiled what they query:

- `FUN_40035224` loops over **13 tracks** calling `FUN_4009878a(track_index)`, caching each
  result into `SequencerStates+0x48`. `FUN_4009878a` itself just indexes a **raw global
  byte array `(byte*)0x4056673a[track_index]`** (bounds-checked to 13) — a live,
  ISR-adjacent state table completely outside the C++ Value/Mirror framework this whole
  investigation had been swimming in until now.
- `FUN_400987be` similarly reads a lone global `_DAT_4056676c` (in the same `0x4056xxxx`
  block, 0x32 bytes from the array above).
- `FUN_4009c460` computes `0x1f - LZCOUNT(DAT_4024be38)` — a bitmask→index decode, in a
  *different* memory region (`0x4024xxxx`), used elsewhere for playback-state (stopped/
  playing/recording) checks.

**Found the writers of `0x4056673a`** (`GhidraXrefsTo.java`): a tight cluster of 8
functions all in the `0x4009xxxx` range — a self-contained module distinct from everything
examined in Sessions 1–4. One of them, **`FUN_4009905c`, writes it from 4 separate sites**
— decompiled it (3958 bytes, by far the largest function decompiled cleanly this whole
project) and it is unmistakably **the AR's per-tick sequencer engine**:

- Opens by clearing an interrupt-pending bit in ColdFire on-chip peripheral space:
  `_DAT_fc048010 = _DAT_fc048010 & 0xfdffffff;` — confirms this runs in tick/ISR context.
- Maintains `DAT_40566754`/`DAT_40566755`/`DAT_40566756` as **current / pending-next /
  previous pattern index** — e.g. `if (DAT_40566754 != DAT_40566755) { FUN_40001236(...) }`
  (notify on a real pattern change) followed later by the literal commit
  `DAT_40566754 = DAT_40566755;`.
- Indexes a **separate, flattened, real-time pattern-data table** at
  `0x40b6a620 + pattern_index * 0x14f00` — a completely different, much larger
  (85,760-byte) per-pattern representation than the C++ `Pattern` object (1468 bytes) this
  project has been tracing since Session 3. This is presumably a "compiled"/performance
  representation the engine reads directly, separate from the editable project-data model.
- Has a clear two-phase pattern-change shape: a step-counter reaches a **look-ahead
  trigger** (`DAT_405666e6 == '\x02'`, i.e. 2 steps before pattern end) → calls
  `FUN_40097e84()` to compute the actual next pattern into `DAT_40566755`, and
  `FUN_40097c2c(DAT_40566755)` — then, when the step counter actually reaches the pattern
  boundary (`DAT_405666e6 == '\0'`), commits: `DAT_40566754 = DAT_40566755` plus a cluster
  of position/reset bookkeeping. **This two-phase precompute-then-commit shape is exactly
  where a PTN CHG mode check would plausibly live** — SEQUENTIAL waits for the boundary
  (what's shown here), while DIRECT START/DIRECT JUMP would need to take a *different*
  branch that doesn't wait.

**Not yet found**: the actual mode check itself. Everything decompiled so far shows the
SEQUENTIAL-shaped wait-for-boundary path; no branch keyed on a 4-valued PTN CHG mode field
has been identified yet inside this function or its neighbors.

### Traced the pattern-select request all the way to a real switch dispatcher  [MEASURED]

`FUN_40097e84`/`FUN_40097c2c` (the two functions `FUN_4009905c` calls at its "precompute"
point) turned out to be **SONG/CHAIN-mode** logic (a distinct AR feature — patterns
auto-advancing in a programmed chain), not PTN CHG — `FUN_40097c2c` sends a MIDI-out
message (`thunk_FUN_40083978(2, ...)`, a 2-byte MIDI call, plausibly Program Change) when
the chain's next pattern differs from the last one sent. Real, useful sequencer knowledge,
but a different feature. Retracting it as the PTN CHG lead specifically.

That prompted a cleaner hypothesis: search for whoever **writes** `DAT_40566754`
(current pattern) and `DAT_40566755` (pending pattern) *from outside* `FUN_4009905c`
itself — that's the UI-facing "request a pattern change" entry point.

- **`FUN_40097fee`** turned out to be **boot-time init**, not a runtime request handler —
  but it's a great confirmation: `_DAT_400001e4 = FUN_4009905c;` installs `FUN_4009905c`
  as an **interrupt vector**, alongside ColdFire interrupt-controller config writes
  (`DAT_fc04806c`, `DAT_fc048079`, `DAT_fc04c07e`) — conclusively confirms it's the tick
  ISR, not just "some function that happens to touch these globals."
- **`FUN_40098880(param_1)`** is the real one: `if (param_1 < 0x80) { DAT_40566755 =
  param_1; _DAT_40566760 = 0; _DAT_40566764 = -1; }` — a clean "request pattern `param_1`
  (0–127, matches the known pattern count)" function that only ever touches the **pending**
  slot, never the current one directly.
- **`FUN_40098880` has exactly one caller in the whole binary**: `case 0xc` inside a real
  switch statement, `switchD_400a1e5e`, at function `0x400a219c` (1828-byte body). Ghidra's
  own switch-table recognition worked here (unlike `FUN_4003fc14`'s if/else chain) — this
  is a **completely different, much lower-level dispatcher** than `PatternSelectionView`'s
  UI handler: cases cover transport, MIDI clock, and other core-sequencer messages, not
  view-specific UI concerns. `case 0xc`'s body checks a message subtype
  (`FUN_40072590() == 5`) and a validated pattern-index byte field before calling
  `FUN_40098880`.

**Notable structural correlation with the OT project**: this dispatcher's address,
`0x400a1e5e`, is startlingly close to the OT firmware's own long-studied core sequencer
function, `FUN_400a1eea` (OT NOTES.md, referenced throughout this task's own brief) — only
~0x8c (140) bytes apart. Both firmwares share the DPS-1-style platform hypothesis from
Session 1; this is the first concrete *address-level* echo of that shared heritage found
in this project, and a genuinely promising sign for task step 4 (once step 3 is solid):
if these two functions really are cognate, whatever invariant the AR maintains here may
map close to 1:1 onto where the OT's own patches have been landing.

**Still not found**: an explicit branch keyed on the 4-valued PTN CHG mode anywhere in
this chain. `case 0xc`'s only visible branching is the subtype/range check, not a mode
check. The remaining hypothesis: the mode is read *inside* `FUN_4009905c`'s own
precompute/commit boundary logic (the large boolean expression gating early triggering at
step `0x02`), reading a field from the flattened per-pattern table at
`pattern_index*0x14f00 + 0x40b6a620` — several such field reads are already visible in the
Session 5 `FUN_4009905c` decompile excerpt (e.g. `*(char*)(iVar7+0x14eb9)`,
`*(short*)(iVar7+0x14eb3)`, `*(char*)(iVar7+0x354)`) but none has yet been confirmed as a
4-valued PTN CHG mode specifically — this needs closer reading, not another new lead.

### Checked one flattened-table field via raw listing — boolean, not the mode  [MEASURED]

Per the process note from Session 4 (don't re-read dense decompiled C by eye when the raw
listing is cleaner), pulled Ghidra's raw instruction listing for the precompute-boundary
region (`0x40099500`–`0x400996c0`). Found a clean, unambiguous field test:

```asm
; A2 = (flag<0 ? DAT_40566756 : DAT_40566754) * 0x14f00 + 0x40b6a620   -- selects
;      previous-pattern's or current-pattern's flat record based on a context byte
mvs.b  (0x0,A2,D1*0x1), D1     ; D1 = sign-extend *(A2 + 0x14eb9)   [D1 was #0x14eb9]
cmp.l  D1, D7                  ; D7 = 1
bne.b  0x40099564              ; if field != 1: D1 = DAT_40566774 (a global default)
                                ; if field == 1 (fallthrough): D1 = *(context_struct - 0x52)
```

Field `pattern_record + 0x14eb9` is tested against the literal `1`, not a 4-way range —
**this reads as a per-pattern boolean flag, not the 4-valued PTN CHG mode.** Plausibly
something like "override step-length from context" or similar. Ruling it out as the PTN
CHG field specifically, but recording the exact test shape here since it's now a template
for checking the *other* nearby field offsets (`0x14eb3`, `0x14eb5`, `0x354`, and whatever
else appears in this same record) the same mechanical way — via raw listing, not
decompiled C, and looking specifically for a compare against a small range (0–3) or a
4-entry jump table rather than a single-bit test.

### Exhaustively checked all pattern-record fields FUN_4009905c touches — none is it
   [MEASURED — strong negative result]

Extracted `FUN_4009905c`'s full raw instruction listing (1107 instructions) and
mechanically grepped for every distinct offset into the flattened per-pattern record
(base `0x40b6a620`, stride `0x14f00`) the function references. **Only four exist**:
`0x14eb3`, `0x14eb5`, `0x14eb9` (already checked, boolean), `0x14eba`. Checked the other
three's exact usage via raw listing:

- `0x14eb3`, `0x14eb5`: both accessed as 16-bit words (`mvs.w`/`movea.w`), feeding step-
  count/loop-length arithmetic (`% field == 0`, `<= step_counter` comparisons) — pattern
  length / loop-count fields, not a mode.
- `0x14eba`: accessed as a byte, used purely as an **index into a lookup table**
  (`DAT_401a8ff0 + field*4`, with a `-1` adjustment) — reads as a scale/note-mapping
  index, not a mode enum.

**None of the four is a 4-way branch or anything resembling SEQUENTIAL/DIRECT START/
DIRECT JUMP/TEMP JUMP.** This is a real, mechanically-verified negative result:
**the PTN CHG mode is not read anywhere inside `FUN_4009905c`.** Whatever implements the
behavioral difference between the four modes must live either in a sibling function in the
same `0x4009xxxx` module (the other confirmed writers of `0x4056673a`/`0x4056676c` found
earlier this session — `FUN_40098226`, `FUN_4009867a`, `FUN_4009a3e2`, etc. — none
decompiled yet), or in a part of the flattened per-pattern record this function simply
doesn't touch (it's 0x14f00 = 85,760 bytes total; only a handful of offsets near its tail
have been examined at all).

### Checked the module-cluster's other functions — all transport/reset, not PTN CHG
   [MEASURED]

Decompiled the three other confirmed writers of `0x4056673a`/`0x4056676c`:

- **`FUN_40098226`** (1108 bytes): initializes/restarts playback of the *current* pattern
  (`DAT_40566754`) from step 0 — resets all 13 tracks' step counters, timing, etc. Reads
  the same `0x40b7f4d9`/`0x40b7f4da`-offset fields seen in `FUN_4009905c` (pattern length/
  scale lookups), nothing new mode-shaped.
- **`FUN_4009867a`** and **`FUN_4009a3e2`**: both are playback-stop/reset handlers (zero out
  all per-track state, timing counters, MIDI-related flags). `FUN_4009a3e2` additionally
  resolves a pattern via the **song/chain table** (`0x4168xxxx` region, same one
  `FUN_40097e84` used) and calls `FUN_4009a2ae` (a `DAT_40566754` writer) with it — i.e.
  "stop and rewind to the chain's first pattern."
- **Found who calls `FUN_40098226`/`FUN_4009a3e2` together: `FUN_400411e8`, confirmed via
  its own strings (`LIVE REC: QUANTIZED/UNQUANTIZED`, `STEP REC: STANDARD/JUMP`) to be
  `TransportView`'s own event handler** — i.e. this is the **PLAY/STOP/RECORD button**
  handler, not a pattern-selection screen at all. Its `event == 0x51` branch is STOP
  (`FUN_4009a3e2(0,0)`); its PLAY-button path branches on `FUN_400351d4(...)` (plausibly
  "is chain/song mode active?") between "just restart current pattern"
  (`FUN_40098226(uVar4)`) and "stop, rewind to chain start, then restart"
  (`FUN_4009a3e2(0,0); FUN_40098226(0);`).

**None of this is PTN CHG mode logic** — it's genuine, adjacent transport/song-mode
machinery, confirmed by tracing rather than assumed. Recording it so it isn't re-walked:
the whole `FUN_40098226`/`FUN_4009867a`/`FUN_4009a3e2`/`FUN_400411e8` cluster is now
understood and can be set aside.

### Honest state after this session's bottom-up push

Four strong, concrete leads chased to ground this session (the tick engine's own field
reads, `FUN_40097e84`/`FUN_40097c2c`, the `0x4009xxxx` module cluster, `TransportView`'s
handler) — all real sequencer/transport code, **none of them the PTN CHG mode check**.
This doesn't mean the bottom-up approach was wrong (it produced the single biggest
structural finding of the whole project, the tick engine itself, in the first few steps) —
it means the specific mode-check site is in a part of this engine not yet reached. Two
honest possibilities going forward: (a) it's a genuinely small, easy-to-miss branch
somewhere in the ~80KB of code this cluster spans that just hasn't been the one checked
yet, or (b) it's reached through a *different* entry point than pattern-select/play/stop —
e.g. specifically through whatever handles a pattern-select action *while already
playing* (the actual DIRECT JUMP use case), which may be a still-undiscovered function,
possibly closer to `case 0xc`'s sibling cases in `switchD_400a1e5e` that weren't
individually decompiled this session.

### Read through `switchD_400a1e5e`'s other cases; checked `FUN_400b3980`  [MEASURED]

Re-examined the full `switchD_400a1e5e` decompile (already captured earlier this session)
case by case, looking specifically for one reachable while already playing (the actual
DIRECT JUMP scenario) rather than `TransportView`'s PLAY/STOP path. Nothing among the ~38
cases obviously matches — most are kit/sound-parameter events (`0xe`–`0x15`, all sharing
the shape `FUN_40157fb8(); FUN_4009fXXX();`), sample/file linked-list traversal
(`0x16`–`0x19`, `0x1f`), MIDI clock/tempo-sync bookkeeping (the `0x21`/`code_r0x400a219c`
loop), or generic notify dispatch (`0xb`, `0x1d`). One near-miss: **`case 0x25`** branches
on a value at `*(unaff_A2+4)` against `0`, `3`, and `4` specifically (not a contiguous
0–3 PTN-CHG-shaped range) calling into an unrelated `0x400f3xxx` address cluster — checked
and set aside as a different feature (not decompiled further; the non-contiguous case
values are enough to rule it out as PTN CHG's own enum).

Checked **`FUN_400b3980`** (called by cases `0x1a`/`0x1b`, both of which also call the
`FUN_400352d4` tristate poller found earlier): it's the **tempo setter** — clamps an
input to `0xe0f`–`0x8ca1` (a BPM×10-scaled range, ~36–360 BPM), writes it through the
generic `getMirror()`/`notify()` pattern. Cases `0x1a`/`0x1b` are tempo-encoder turn
handling, unrelated to PTN CHG.

**This closes out every concrete lead surfaced by this session's bottom-up push.**
Genuinely major structural progress was made (the tick engine, its ISR registration, the
pattern-select request path, the transport handler, tempo handling, song/chain-mode
plumbing) — but the PTN CHG mode check itself was not found among any of it. The one
important caveat for whoever continues: the "exhaustive" field-offset check of
`FUN_4009905c` (four `0x14eXX` literals) only catches *literal* immediate offsets — a
field reached through a computed/indirect offset (e.g. a small lookup table keyed by
track or event type) would not have shown up in that grep, and hasn't been ruled out.

### Old, now-superseded NEXT (for reference, from Session 5)

Every concrete lead Session 5's bottom-up push surfaced organically had, at that point,
been checked. Item 1 below (the offset-scanning tool) is what Session 6 built and used —
see the new Session 6 section and its own NEXT list for the current state.

1. **Build the offset-scanning tool flagged as a caveat above**, rather than continue by
   hand: a script that, for a given function, lists every memory access whose base is
   `DAT_40566754`/`0x40b6a620` (the flattened pattern table) *including* computed/indirect
   ones (register-plus-register addressing, not just literal immediates) — this is the
   concrete gap that let the `FUN_4009905c` field check quietly miss anything reached
   through a lookup table rather than a fixed offset.
2. `FUN_40097724`, `FUN_40097c00`, `FUN_40097c18`, `FUN_400976f6` — four members of the
   `0x4009xxxx` module cluster referenced from `FUN_4009905c`/`FUN_40098226`, still not
   individually decompiled. Lower priority than (1) since the pattern so far is "more
   transport/reset plumbing," but not yet ruled out.
3. Consider whether PTN CHG's mode might not be consulted by *this* engine at all during
   normal playback, but only at the moment a pattern change is *requested* — i.e. back in
   `case 0xc`'s own body (already read once, but worth a second, more careful pass now
   that the surrounding architecture is much better understood) or in whatever validates
   the pattern-index byte before calling `FUN_40098880`.
4. If a mode-check is found, confirm it reads from the flattened `0x40b6a620 +
   pattern_index*0x14f00`-based table (not the C++ object model) — if so, the PTN CHG mode
   byte's offset within that 0x14f00-byte record is the concrete target, and the earlier
   Sessions 3–4 C++-side search (`PatternSettings`, `patternSettingsStorage_v1_t`) was
   looking in the wrong representation entirely (the editable project model, not the
   engine's own compiled/runtime copy) — worth an explicit note for whoever continues,
   since it reframes three sessions of C++-side searching as not wrong, just aimed at a
   different (also real, just not engine-facing) layer of the same data.
5. This remains the most promising lead of the whole project so far — prioritize it over
   resuming the UI-side `PopupWindow` confirm-flag thread.

## Session 6 (2026-09-20) — built a mechanical table-access scanner; found the boundary-commit mechanism and its request dispatcher

### Built `tools/ghidra/GhidraFindTableAccess.java`  [DONE]

Per the caveat closing Session 5, built the flagged tool: for a given function, it walks
the decompiled high P-code, and for every `LOAD`/`STORE` op does a bounded backward slice
through the address varnode's def-chain (through `INT_ADD`/`INT_MULT`/`PTRADD`/`PTRSUB`/
`COPY`/`CAST`/`MULTIEQUAL`/`INDIRECT`/sign-zero-extend), flagging any op whose chain
touches the flattened table's base constant (`0x40b6a620`), its per-record stride
(`0x14f00`), or a `LOAD` of one of the pattern-index globals (`DAT_40566754/55/56`). This
catches indirect/computed table accesses a literal-offset grep over decompiled C text
cannot — the exact gap Session 5 flagged.

**Validated against a known-positive control** (`FUN_4009905c` itself): found all 4
previously-known literal offsets (`0x14eb3/b5/b9/ba`) *plus* several genuinely new ones
the manual grep had missed entirely (see below) — 45 matching ops total, confirming the
tool actually works rather than silently missing everything.

**Known limitation, recorded rather than glossed over**: the tool's reported
`offsets=[...]` list is every constant seen anywhere in the bounded backward slice, not
necessarily all part of the same literal address expression — a `MULTIEQUAL` (phi) node
merges values from multiple predecessor blocks, so a downstream use can pick up a constant
that only applies on a control-flow path that particular use doesn't actually take. Every
offset this session treats as meaningful was cross-checked against Ghidra's raw
instruction listing before being trusted — **the tool is a lead-generator, not a
ground-truth source by itself.**

### Ran it against the whole surviving lead list — clean, mechanically-verified negatives  [MEASURED]

- **`switchD_400a1e5e`'s true containing function (`FUN_400a1518`, all ~38 cases)**: zero
  matches. The entire request-dispatch switch — not just `case 0xc`, every case — never
  touches the flattened table or the pattern-index globals, directly or indirectly. This
  mechanically closes Session 5 NEXT-list item 3: the PTN CHG mode is **not** consulted
  inline in the dispatch path.
- **`FUN_40098880`** (the pattern-select request handler, `case 0xc`'s callee): zero
  matches. Confirms it really is just the raw index-validate-and-store
  (`if (idx<0x80) DAT_40566755=idx`) Session 5 already found.
- **`FUN_4009867a`, `FUN_400b3980`, `FUN_400411e8`, `FUN_40097e84`, `FUN_40097c2c`**: all
  zero matches, mechanically confirming Session 5's by-eye rulings.
- **The four still-unexamined module-cluster members from Session 5 NEXT item 2**
  (`FUN_40097724`, `FUN_40097c00`, `FUN_40097c18`, `FUN_400976f6`): all zero matches.
  Ruled out as PTN CHG candidates without needing individual manual decompiles — closes
  Session 5 NEXT item 2 outright.

### New record fields found this way, raw-listing-confirmed — not the mode, but real new territory  [MEASURED]

- **`FUN_40098226`** touches a previously-unknown **per-track sub-array** inside the
  flattened record: base offset `0x2c5`/`0x2c7`, stride `0x395`, 13 entries (raw listing
  confirms the loop bound `0x2e91 = 13 * 0x395`, matching the already-known 13-track
  count). Reads as byte/string-copy plumbing (label characters, a per-track override byte
  with a shared-default fallback) — not a mode field.
- **`FUN_4009a3e2`** touches two more new fields, both confirmed by decompiling their sole
  consumers: **record+`0xe4b7`** (signed byte; negative ⇒ fall back to a global default
  note — `FUN_401188ec` sets that default when `0 ≤ value < 0x80` — a per-pattern MIDI
  note override) and **record+`0xe4bc`** (uint16, fed straight into `FUN_401184ae`, which
  clamps it to `0xe10`–`36000` — the exact same BPM×10 range as the tempo setter — a
  **per-pattern tempo override**). Neither is 4-valued; both ruled out as PTN CHG
  specifically, but now concretely characterized rather than left as unexplained offsets.

### Found the boundary-commit mechanism inside `FUN_4009905c`  [MEASURED — the mechanism itself; mode-attribution still open, see below]

Raw-listing read of `0x400990e0`–`0x40099280` (the region the new tool's hits pointed at)
turns out to be the tick engine's **pattern-switch commit block**, structured as a
countdown:

- `DAT_405667e4` is a **countdown**: when a "recompute" flag (`DAT_405667e8`) is set, it's
  re-derived as `lookup_table[current_pattern.record[0xe4ba]] - DAT_405666e6` (steps
  remaining until the current pattern's own boundary, via the same `0x401a8ff0` lookup
  table already known from field `0x14eba`'s "scale/resolution index" role). Every tick,
  if nonzero it's decremented; **only when it reaches exactly 0** does the block below run.
- The commit itself, verbatim: `DAT_40566756 = DAT_40566754` (previous = old current),
  then **`DAT_40566754 = DAT_40566755 = DAT_405667dc`** (both current *and* pending are set
  from a third global, `DAT_405667dc` — "resolved next pattern index"). This is the literal
  pattern-switch.

So the state machine is: some request path writes `DAT_405667dc` (what to switch to) and
sets `DAT_405667e8` (recompute-the-countdown), and the switch actually happens only when
`DAT_405667e4` counts down to the current pattern's own natural boundary. This is almost
certainly the mechanism behind SEQUENTIAL/TEMP-JUMP-style deferred switching.

**Found the two writers of `DAT_405667dc`** (via `GhidraXrefsTo.java` — the only other
reference is `FUN_4009905c` itself, reading it at the commit line):

- **`FUN_4009884c(param_1)`**: `if (DAT_405666e0==1) { DAT_405667e8=1; DAT_405667dc=param_1; DAT_4056682c=1; }` — queues a pattern change for the next boundary, only while `DAT_405666e0` (a playback-state byte) `==1`.
- **`FUN_4009a5b0(param_1, param_2)`**: same shape but two params — if `DAT_405666e0==1`, queues (also writing `DAT_405667e0=param_2`); if `DAT_405666e0==0` (stopped), instead does an **immediate** song/chain-table lookup and writes `DAT_40566754` directly, no countdown at all — i.e. this one function alone has both a queued path and a bypass path, selected by *playback state*, not (as far as decompiled so far) by PTN CHG's own mode.

**Found their one shared caller: `FUN_4003e636(param_1, param_2)`** (`param_2` = requested
pattern index, `< 0x80` guarded) — a genuine dispatcher between three different ways of
applying a pattern change:

1. If `*(byte*)(*(int*)(param_1+0x70) + 0x44)` (`cVar5`, read via the trivial one-line
   getter `FUN_400351d4`) is true **and** a separate byte at `param_1+0xc6` is nonzero:
   clears that byte and calls `FUN_4009884c(param_2)` directly — the queued path above.
2. Otherwise, after a block of view/selection bookkeeping (`FUN_400b6502/9088/6532/674a`,
   `FUN_4009a9e0`/`FUN_4009aac8`), it calls `FUN_400b3d1e(uVar7)` — a helper that reads a
   value via a vtable call (`(**(code**)(*obj+0x28))(obj)`) and clamps its `+0x30` field to
   `{0,1,2}` — and branches three ways on the result: `==1` ⇒ `FUN_4009a5b0(param_2, 1)`;
   `==2` ⇒ `FUN_4009a5b0(param_2, 0)`; otherwise (default/no context) ⇒ **`FUN_4009a2ae(param_2)`
   called directly** — skipping the queued mechanism and both request functions entirely,
   an **immediate** write with no countdown wait at all.

**Honest confidence marker — this is the most important open question right now.**
`FUN_4009a2ae` writing `DAT_40566754` directly, with no countdown gate, is exactly the
*shape* of a DIRECT-JUMP-style bypass. But the two things selecting between the three
paths here — `cVar5` (a one-byte getter off a sub-object at `param_1+0x70`) and
`FUN_400b3d1e`'s `{0,1,2}` classification (which reads like a chain/song-context type, a
*different*, already-known AR feature, not obviously PTN CHG's own 4-valued enum) — have
**not yet been confirmed** to be reading PTN CHG's SEQUENTIAL/DIRECT START/DIRECT
JUMP/TEMP JUMP setting specifically. It's entirely plausible this branching is actually
about song/chain-context rather than PTN CHG at all, and the real PTN CHG mode read
happens somewhere still unfound — inside whichever function sets `param_1+0xc6`, or a
still-unidentified caller upstream of `FUN_4003e636` itself. **Do not treat
`FUN_4009a2ae`/`FUN_4009884c`/`FUN_4009a5b0` as "the DIRECT JUMP mechanism, confirmed"
until this is resolved** — treat it as the strongest lead so far, not yet a finding.

### NEXT for this thread (highest priority)

1. Find every caller of `FUN_4003e636` — almost certainly (a) `PatternSelectionView`'s
   confirm/OK handler, (b) a grid-button pattern-select-while-playing handler, or both.
   Confirming which UI entry point(s) reach it, and under what circumstances
   `param_1+0xc6` gets set, is the fastest path to resolving the mode-attribution question
   above.
2. Independently: find where PTN CHG's own 4-entry mode setting is actually *stored* (the
   field the `PTN: SEQUENTIAL/DIRECT START/DIRECT JUMP/TEMP JUMP` picker writes to, from
   Session 1/3's UI-side work) — then check whether that storage location is read anywhere
   in `FUN_4003e636`'s call chain (`cVar5`'s sub-object at `param_1+0x70`, or upstream of
   `param_1+0xc6`'s write). This directly answers the open confidence-marker question
   above and is probably the single highest-value next action.
3. Decompile **`FUN_4009a2ae`** itself (referenced several times this session as "the
   immediate-write path" but never actually read) — confirm it really does write
   `DAT_40566754` with no countdown/gate, and check whether it also writes
   `DAT_40566755`/`DAT_40566756` or resets anything else a true instant jump would need to
   reset (step counters, mirrors, etc.) — this is task step 3's "what makes it correct"
   question starting to become answerable.
4. Do not start on OT adaptation (task step 4). This is the closest the project has come
   to task step 3's actual deliverable, but the mode-attribution gap above means it is not
   yet solid. Six sessions in, still correctly not skipping ahead.

## Session 6, continued — mode-attribution question resolved; the DIRECT START vs DIRECT JUMP distinction found

`ar-kyoti-fw` published to GitHub this session (`github.com/Zac-Kyoti/ar-kyoti-fw`,
pushed by the user directly — `gh repo create --push` was blocked for the assistant by
the CLI's own auto-mode policy as a "Create Public Surface" action; noted here in case a
future session hits the same wall and wonders why `origin` didn't get set up the usual
way).

### `DAT_405667e0` (the second global `FUN_4009a5b0` writes) is the DIRECT START vs DIRECT JUMP switch  [MEASURED]

Xref'd `DAT_405667e0` (`FUN_4009a5b0`'s `param_2`, previously unread). **Exactly one
reader, in `FUN_4009905c` right after the commit block**, at `0x40099252`
(this is inside the raw-listing range already captured earlier this session, just not
interpreted yet):

```asm
tst.l   (0x405667e0).l
bne.b   0x4009927a                  ; DAT_405667e0 != 0: D0 = 0
; -- fallthrough, DAT_405667e0 == 0 --
D1 = new_pattern.record[0x14eb3]    ; per-pattern step-length field (already known)
D2 = DAT_405666e4 (a running tick/step counter)
if D1 < 1: D0 = D2
else:      D0 = D2 mod D1           ; divsl.l
0x4009927a: D0 = 0                  ; (the bne target)
```

**This is the DIRECT START vs DIRECT JUMP distinction, mechanically confirmed**:
`DAT_405667e0 != 0` ⇒ new pattern starts at step **0** (restart — DIRECT START's defining
behavior); `DAT_405667e0 == 0` ⇒ new pattern starts at `old_step mod new_pattern_length`
(**keep playhead position, wrapped into the new pattern's length** — DIRECT JUMP's
defining behavior, switch without losing your place). `D0` here feeds forward into
`0x4009927c`'s onward code (not yet traced further, but this is clearly "the step index
the newly-current pattern resumes at").

### The countdown is short (next-step-boundary, not next-pattern-boundary)  [MEASURED]

Dumped the first entries of the `0x401a8ff0` lookup table (the one field `0x14eba`/`0xe4ba`
indexes into) directly from the extracted binary: **`3, 4, 6, 8, 12, 24, 48`**, then
non-numeric-looking data — a short table of small integers, reading as PPQN-style
ticks-per-step values for different step-resolution settings (classic 24-PPQN-family
subdivisions), not a ticks-per-*pattern* table. This settles an open question from
earlier in the session: `DAT_405667e4`'s countdown (`table[...] - DAT_405666e6`) is **the
number of ticks until the next step/resolution boundary — at most a few dozen ticks, a
small fraction of a bar** — not a wait for the whole current pattern to finish. Both
DIRECT START and DIRECT JUMP commit within one short step-quantized wait, never the full
remaining length of the currently-playing pattern.

### `FUN_4009a2ae` decompiled — confirmed as a synchronous, unconditional "set pattern now" primitive  [MEASURED]

```c
void FUN_4009a2ae(uint param_1) {
  if (param_1 < 0x80) {
    DAT_4056675c = -1;
    DAT_40566754 = (char)param_1;         // current pattern, written directly
    DAT_40566758 = 0;
    FUN_40099fd2(param_1, -1);            // step/position reset
    FUN_40097c2c(DAT_40566754);           // song/chain-mode bookkeeping (Session 5)
    // re-apply the new pattern's note/tempo overrides (0xe4b7/0xe4bc, Session 6 earlier)
    FUN_401188ec(note_override_or_default);
    FUN_401184ae(*(uint16*)(new_pattern_record + 0xe4bc));
    FUN_40001236(...); FUN_40001236(...);  // generic notify, twice
  }
}
```
No countdown, no `DAT_405667dc`/`DAT_405667e8` involvement at all — this writes
`DAT_40566754` synchronously and does a full reset-and-reapply (step position, song/chain
state, per-pattern note/tempo overrides, notify). Called from `FUN_4009a5b0` itself (its
`DAT_405666e0==0`, i.e. **stopped**, branch) and from `FUN_4003e636`'s own default/`cVar5`
branch — both readings are consistent with "apply immediately because there's no running
playback position to quantize against," not "this is DIRECT JUMP's bypass."　This
resolves Session 6's earlier speculation that `FUN_4009a2ae` was itself the DIRECT-JUMP
fast path: **it isn't mode-specific at all — it's the stopped/no-context immediate
setter**, called by multiple modes' code paths whenever there's nothing to quantize
against.

### Found the caller of `FUN_4003e636` — and it resolves the whole mode-attribution question  [MEASURED, high confidence]

`FUN_4003e636` has exactly two call sites, both inside `FUN_4003fc14` — the same huge
multi-feature UI dispatcher Session 1 already tied to the PTN CHG string table
(`0x400407f6`). Raw listing at the first site (`0x400400d6`–`0x400400ee`):

```asm
move.l  (0x74,A2), -(SP)        ; push A2+0x74  -- the SAME "item" accessor field
jsr     0x400b3d1e               ; FUN_400b3d1e(A2+0x74)  -- PTN CHG mode reader, called HERE
addq.l  #0x4, SP
tst.l   D0
beq.w   0x400401fc               ; mode == 0 (SEQUENTIAL) -> skip FUN_4003e636 entirely!
move.l  (-0x20,A6), -(SP)        ; param_2 = requested pattern index
move.l  A2, -(SP)                ; param_1 = this
jsr     0x4003e636               ; only reached for mode != 0
```

**This is the proof.** The caller reads PTN CHG's mode (via `FUN_400b3d1e` on the exact
same `+0x74` accessor object Session 2 already tied to the PTN CHG picker's own
read/write site, `FUN_400b3db2`) *before* deciding whether to call `FUN_4003e636` at all,
and **skips it entirely when the mode is SEQUENTIAL (0)**. So:

- **SEQUENTIAL** (mode 0): `FUN_4003e636`/`FUN_4009a5b0`/`FUN_4009884c`/the countdown
  commit block are never reached via this path at all. (Where the plain "queue in
  `DAT_40566755` and let the pattern finish naturally" behavior actually lives has not
  been re-confirmed this session, but Session 5 already found `FUN_40098880` doing exactly
  that unconditionally — plausibly this caller does that write *before* the code segment
  captured here, i.e. always queues the pending slot first, then this block layers
  DIRECT-mode-only early application on top. Not yet verified line-by-line; flagged as
  inferred, not measured.)
- **DIRECT START** (mode 1) and **DIRECT JUMP** (mode 2): `FUN_4003e636` is called, and
  (mode-attribution now confirmed, since we know the exact mode value at the point of
  the call) — assuming `FUN_4003e636`'s internal `FUN_400b3d1e` re-read returns the same
  value as this caller's own read (near-certain, nothing rewrites the mode field in
  between) — routes to `FUN_4009a5b0(pattern, 1)` for DIRECT START and
  `FUN_4009a5b0(pattern, 0)` for DIRECT JUMP, i.e. exactly the queued/countdown-gated,
  step-quantized commit path with the position-reset-vs-keep distinction found above.
- **TEMP JUMP** (mode 3, raw): `FUN_400b3d1e` saturates any value `≥3` to `2`, so TEMP
  JUMP is **indistinguishable from DIRECT JUMP at this layer** — same call
  (`FUN_4009a5b0(pattern, 0)`), same keep-position behavior. Confirms Session 2's
  speculation (b): the real persisted/consulted enum at this storage layer is 3-valued;
  TEMP JUMP's distinguishing "reverts afterward" behavior must be implemented via separate
  bookkeeping not yet located (plausibly using the already-known `DAT_40566756`
  "previous pattern" slot to snap back later) — a genuinely open item, but a narrow,
  well-scoped one, not a blocker for understanding the core immediate/deferred mechanism.

### Where this leaves task step 3 — the mechanism is now understood; the "why it's correct" question is next  [status]

The full request→commit pipeline for DIRECT START/DIRECT JUMP/TEMP JUMP is now traced
end to end, all of it mechanically measured rather than inferred: UI mode read
(`FUN_400b3d1e` on the picker's own storage field) → conditional dispatch
(`FUN_4003e636`) → queue write (`FUN_4009a5b0`, storing both the resolved target pattern
*and* a start-position-behavior flag) → per-tick countdown gated on a short,
step-resolution-scaled wait, not a full-pattern wait (`FUN_4009905c`, `DAT_405667e4`/
`DAT_405667e8`/`DAT_405667dc`) → atomic commit (`DAT_40566754`/`DAT_40566755` written
together) → mode-dependent step-position resume (`DAT_405667e0`, reset-to-0 vs
modulo-keep).

**The invariant this session's evidence points to, stated plainly**: AR's DIRECT JUMP is
not "switch mid-instruction, no quantization" — it is "switch at the very next
step/resolution boundary (a handful of ticks away), keeping timeline position, via the
*same* atomic current/pending-write the natural end-of-pattern path presumably also uses."
The "atomic" part may be exactly the missing invariant task step 3 exists to find: current
and pending are written **together, in the same two instructions**
(`DAT_40566754 = DAT_40566755 = DAT_405667dc`), gated by a single countdown that's
recomputed fresh (`DAT_405667e8`) every time a new request arrives — there is no
window where one is updated and the other lags, and no separate "apply-now" write path
that could race against the tick engine's own read of the current-pattern pointer
elsewhere in the same function. This is a genuinely promising candidate for "what OT's
own three ColdFire-register fixes have been missing" but **has not yet been compared
against OT's own DIRECT JUMP code at all** — that comparison is task step 4 and is still
explicitly out of scope until this AR-side picture is double-checked once more (see NEXT).

### NEXT for this thread (highest priority)

1. **Sanity-check the SEQUENTIAL path inferred above**: read the part of `FUN_4003fc14`
   *before* `0x400400c0` (this session only looked at and after the `FUN_400b3d1e` mode
   check) to confirm whether `DAT_40566755` (or another plain queue write) really does get
   set unconditionally regardless of mode, before the DIRECT-mode-specific block layers on
   top. This is the one piece of this session's picture still marked inferred rather than
   measured.
2. **Locate TEMP JUMP's revert bookkeeping** — low priority for task step 3's core
   deliverable (the immediate/deferred mechanism is understood without it), but worth a
   session if time allows, since "temporarily jump then return" is exactly the kind of
   invariant-heavy feature that could contain another lesson for OT.
3. **Begin the actual task step 3 deliverable in earnest**: write a clean, standalone
   summary of the confirmed mechanism (the atomic paired write, the fresh-countdown-per-
   request invariant, the step-quantized — not pattern-quantized — timing) independent of
   this session-log narrative, so it can be directly compared against OT's own DIRECT JUMP
   code without having to re-derive it from NOTES.md's chronological trail each time.
4. **Only after (3) exists as a standalone writeup**, start task step 4: read OT's own
   three previously-proven-exact-in-emulation ColdFire register fixes side by side with
   this mechanism and look specifically for where OT's implementation might *not* have an
   equivalent to the atomic paired write / fresh-per-request countdown recompute. Still
   not started. Six-plus sessions in — this is the first time starting task step 4 is
   actually defensible, not just "not yet time."

### NEXT (superseded UI-side thread, kept for reference — lower priority now)

The picker-construction lead is exhausted — don't re-enter it. Two directions remain:

1. **Find who reads `PopupWindow+0x30` (the "confirmed" flag, `FUN_40076cb8` sets it to 1
   on event `0x45`).** That reader is the code that performs the actual write-back — this
   is now a precise, concrete target rather than a vague "find the confirm handler."
   Likely candidates: the popup's owner polling it on a subsequent tick, or a shared
   "modal dialog pump" function called once per UI frame that checks every active popup's
   `+0x30`. `PopupWindow`'s remaining vtable slots (7 of 22 examined so far: slots 0,1,2,3,
   4 decompiled this session, i.e. `0x4015948c`/`0x40159544`/`0x4007502c`/`0x40076a90`/
   `0x400748a8`, plus slots 0xb/`0x40076cb8` and its callees) are a reasonable place to
   keep looking, but a global search for readers of a fixed offset `+0x30` relative to
   *any* pointer isn't directly mechanizable the way the `+0x2c` field-use search was —
   consider whether `GhidraFindFieldUse.java` can be pointed at a broader candidate list
   (e.g. every function calling into this object, found via the `PatternSelectionView`
   constructor's own later code, since `PatternSelectionView` is presumably the one that
   created this exact popup and is the natural owner to poll it).
2. **Go bottom-up from the sequencer instead of top-down from any UI code.** Three
   sessions of tracing UI construction code (table population, pickers, popups) have
   produced a detailed map of this codebase's generic C++ framework but zero hits on
   PTN CHG's actual storage or the sequencer's read of it. The OT project's own working
   method for finding ITS per-tick engine was not to start from a menu handler either.
   Consider searching for whatever in this AR firmware plays the equivalent role to the
   OT's `FUN_400a1eea` — e.g. by finding the audio/MIDI clock tick's own ISR or a
   `SequencerStates`-adjacent method not yet examined (Session 3 found its constructor and
   ruled out its 4 vtables as destructor-only; its *non-virtual* methods were never
   looked at).
3. Whichever path is chosen, keep using `GhidraStackArgs.java`/`GhidraFindFieldUse.java`
   over hand-tracing wherever a call site's argument layout matters — this session showed
   both that hand-tracing is genuinely error-prone here and that the tooled approach
   resolves it cleanly.
4. Do not start on OT adaptation (task step 4) — four sessions in, still correctly not
   close enough to step 3 being solid. This is tracking (not exceeding) the scale the task
   brief itself predicted.

### Old, now-superseded NEXT (for reference, from Session 3 continued)

Three sessions of manual disassembly on this one dispatcher function have produced two
corrected false leads (Session 2's `FUN_400b3db2`, this session's
implicit trust that `+0x74`-adjacent code was PTN-CHG-specific), and one real (if
ultimately-cleared) methodology hazard (the `a2` reassignment). That is a strong signal to
change approach rather than keep pushing the same technique further:

1. Map the exact call-site arguments at `~0x40040846`–`0x4004088a` (what actually gets
   pushed for `FUN_40158ff8`'s 4 extra stack params) to check for a callback pointer —
   the one specific thread left dangling from this session's trace.
2. If that doesn't resolve it: build a small **tool** rather than keep reading disassembly
   by eye — e.g. a script that, given a function's disassembly, tracks which register holds
   the canonical `this` pointer across the whole function (flagging every `lea.l N(aX),aX`
   self-reassignment) so future offset claims are checked mechanically instead of trusted
   from local context alone. This directly addresses the hazard found this session and
   would make all of Sessions 1–3's remaining raw-disassembly work in this function safer.
3. Once the storage field is genuinely found: confirm by finding the sequencer's reader of
   the same field/offset, and only then assess what makes the real implementation correct
   (task brief step 3's actual deliverable).
4. Do not start on OT adaptation (task step 4) — still not close enough to step 3 being
   solid, three sessions in. This project is tracking the scale the task brief itself
   predicted ("no reason yet to expect this resolves faster" than the OT's own multi-session
   effort), and that's an accurate expectation, not a problem to route around.

### Old, now-superseded NEXT (for reference, from Session 1)

Top-down from the UI (start at the picker, read forward) has hit diminishing returns —
`FUN_4003fc14` is a large multi-feature dispatcher with unreliable decompilation, and two
plausible-looking leads inside it (a jump-table dispatch, `FUN_40137440` as a mode getter)
were both checked and ruled out this session. A different, more structural approach is
likely to pay off better next session:

1. **Try bottom-up instead of top-down**: rather than reading forward from the UI picker,
   look for the *sequencer's* pattern-boundary check directly — by analogy to how the OT
   project originally found its own per-tick engine (`FUN_400a1eea`), not by re-deriving
   it from a menu handler.
   - `SequencerStates::SequencerStates()` is now located (`0x40035350`) with 4 vtables at
     `0x4019a134/0x4019a144/0x4019a154/0x4019a164`. Dump each vtable's function pointers
     (16 bytes = 4 slots each at minimum, likely more — read forward from each base until
     the pointers stop landing in the image's code range) and decompile/disassemble each
     virtual method. One of them is a strong candidate for "apply a pending pattern change
     at the tick/bar boundary."
   - Find `SequencerStates`' `getInstance()`-style accessor (a `StaticSingleton` per the
     RTTI string `StaticSingletonI15SequencerStatesE` — search for xrefs to *that* string,
     not yet done) to find where in the sequencer tick path it actually gets touched.
   - Separately: find the real `Pattern::updateMirror` / `PatternSettings::updateMirror`
     **function bodies** (not their RTTI registration sites found this session) via
     vtable-slot tracing from a `Pattern`/`PatternSettings` instance's own constructor,
     the same way `SequencerStates`' constructor was found this session.
2. Once the pattern-switch commit path is found: identify where it reads the 4-valued mode
   (SEQUENTIAL/DIRECT START/DIRECT JUMP/TEMP JUMP) and how it stays correct — the ordering/
   locking/state-consistency invariants are the actual deliverable this project exists to
   produce (task brief step 3).
3. Do not start on OT adaptation (step 4) before step 3 is solid.
4. **Process note**: when the decompiler output looks structurally implausible (bogus
   stack-var aliasing, calls with no visible args), stop and re-derive from raw
   disassembly rather than reasoning from the pseudo-C — exactly the trap OT's own Session
   70 passes 4–14 fell into before pass 15 retracted them.

## Session 7 (2026-09-20) — sanity-checked the SEQUENTIAL-path claim (partial retraction); wrote the standalone mechanism summary

### The "DAT_40566755 queued unconditionally before the DIRECT block" claim is WRONG as stated — retracted and replaced  [MEASURED]

Per NEXT item 1, disassembled `FUN_4003fc14` from `0x400400a0` (just before the previously-
captured window) through the SEQUENTIAL-mode fallthrough target and onward
(`r2 pd @ 0x400400a0`, `@ 0x400401fc`, `@ 0x40040900`). Session 6's inferred guess —
"plausibly this caller does [a plain DAT_40566755 queue write] before this code segment,
i.e. always queues the pending slot first" — **does not hold as stated and is retracted.**
There is no write to `DAT_40566755` (or any `DAT_405667xx` sequencer global) anywhere in
this function. What's actually there, mechanically confirmed:

- **Unconditional, on every PTN-CHG UI event** (before the mode read at `0x400400d6`):
  `0x400400ac`–`0x400400c6` calls a handler (`0x400363ac` then `0x4007073c`, the latter via
  a function pointer in `a3`) that computes a requested-pattern index into `-0x20(a6)` and
  returns a bool in `d0`. If true: `0x80(a2)` gets a bit set (`or.l d1,0x80(a2)`, `d1 = 1<<d4`)
  — a **"pending picker value changed" dirty bit on the UI dispatcher object itself**
  (`a2`), not a sequencer global.
- **DIRECT (START/JUMP/TEMP) branch** (mode != 0): after `FUN_4003e636` runs, the code
  unconditionally does `0x88(a2) = -1` (sentinel), `0x90(a2) = 0x8c(a2)` (snapshot
  new-into-old), `0x84(a2) = 0` — i.e. it **invalidates the generic pending-value
  bookkeeping**, consistent with "already applied directly, nothing left to commit later."
- **SEQUENTIAL branch** (mode == 0): `FUN_4003e636` is skipped (confirmed already), and
  control falls through the outer event-dispatch chain (`0x400401fc` → ... →
  `0x40040218`'s `bra.w 0x40040920`) to a **generic, PTN-CHG-unaware "value changed?"
  check**: `tst.l 0x88(a2)` (skip if sentinel/negative), `tst.l 0x80(a2)` (skip if dirty bit
  clear), `cmp.l 0x8c(a2),0x90(a2)` (skip if old==new), else call a handler twice via
  `a3 = 0x4015716c` with `(index_ptr, a2+0x8c)` — this reads as a **generic UI-property
  changed-notify dispatcher shared by every field on this object**, not something
  PTN-CHG-specific, and not provably the SEQUENTIAL "queue and let it finish naturally"
  write. Where `0x4015716c` ultimately writes was **not traced this session** — deliberately
  out of scope for a sanity check, and a real open item if the SEQUENTIAL path ever becomes
  load-bearing for the task-3 deliverable (it currently isn't: the deliverable is about
  DIRECT START/JUMP's atomic-commit invariant, which remains fully measured).

**Net effect on the picture**: nothing here changes the DIRECT START/DIRECT JUMP/TEMP JUMP
mechanism reported in Session 6 (still fully measured, still the actual deliverable).
The correction is narrower: the *reason* SEQUENTIAL bypasses the countdown/atomic-commit
mechanism entirely is now precisely characterized (a generic, shared "apply changed picker
value" pathway, not a same-shaped queue write with a different flag), rather than the
previous, wrong, mode-agnostic-queue-write guess.

### Standalone mechanism summary written  [status]

Per NEXT item 3, wrote `MECHANISM.md` — a clean, chronology-free writeup of the confirmed
DIRECT START/DIRECT JUMP/TEMP JUMP request→commit pipeline (mode read → conditional
dispatch → atomic paired queue write → step-quantized per-tick countdown → atomic commit →
mode-dependent step-position resume), intended to be read on its own and compared directly
against OT's own DIRECT JUMP code without re-deriving it from this log's narrative trail.

### NEXT for this thread

1. **Begin task step 4**: read OT's three previously-proven-exact-in-emulation ColdFire
   register fixes (`~/Documents/octatrack-kyoti-fw`) side by side with `MECHANISM.md` and
   look specifically for where OT's implementation lacks an equivalent to the atomic paired
   write or the fresh-per-request countdown recompute. First time this is actually in scope
   per the task brief's own step ordering.
2. Lower priority, unchanged from Session 6: locate TEMP JUMP's revert bookkeeping, and (if
   it ever becomes load-bearing) trace `0x4015716c` to find where the SEQUENTIAL-mode
   generic "value changed" pathway actually writes.

## Session 7, continued — task step 4: compared `MECHANISM.md` against OT's own DIRECT JUMP fix history

**Everything in this section is [INFERRED]**, not measured this session: it is built from a
report of OT's own already-measured findings (`~/Documents/octatrack-kyoti-fw/NOTES.md`
Session 70, passes 4–15), not from fresh disassembly of the OT binary. No OT code or
firmware was touched — this stays within this session's read-only comparison scope, per
`CLAUDE.md`'s "no OT patches until the AR mechanism is solid" constraint (task step 4 is
explicitly the comparison itself, not adaptation).

### OT's three fixes, in one line each

1. **Pass 4/5**: `D7 = resumeStep * newLen` (a step-index quotient-seed fix to the
   per-track `REFILL_TBL` reload). Dynamically proven exact in emulation via fire-timing
   analysis. Flashed: single switches fixed, but a rapid double-switch (A→B→A) broke.
2. **Pass 6**: `SCALE_IX` (`DAT_8000663d`) self-heal — root-caused as a genuine, measured
   **desync bug**: stock derives `SCALE_IX` every step==0 tick from a pattern-blob pointer
   (`A4`) that a plain manual pattern switch **never refreshes**, so `SCALE_IX` can read the
   *old* pattern's scale for an unbounded number of ticks after the switch already
   committed. Fixed via two hooks (one that corrects the value at the commit tick, one that
   replaces stock's stale-`A4`-sourced write outright on every wrap). Proven exact in
   emulation (ten consecutive clean wrap cycles). Not independently reflashed — folded into
   the pass-9 build.
3. **Pass 8/9**: `G_ABSTICK` (a free-running, never-reset, never-wrapped absolute tick
   counter) replacing the previous "re-derive resume position from the outgoing pattern's
   already-wrapped step" model, plus a per-track version of the same fix (each of 8 audio
   tracks' own `REFILL_TBL` slot recomputed as `G_ABSTICK mod trackLen[t]`, independently,
   since per-track SCALE overrides mean tracks don't all share the pattern's own length).
   Both proven exact in emulation against hand-computed ground truth. **Flashed (hardware
   attempt #5 for this thread): symptom unchanged** — "switched-to patterns are still not
   in time... and still exhibit the 'restart' behavior, generally after they pass step 16."

Two independently-exact fixes to two different pieces of step-index arithmetic, plus a
proven-real desync-bug fix, composed together — and the hardware symptom didn't move at
all. Passes 11–14 chased a `FUN_400a1eea` "track 0 special case" hypothesis to explain
this and retracted it in pass 15 as a decompiler misreading; pass 15 leaves the real
mechanism **unfound**, with two prior findings explicitly still standing: (a) the
`REFILL_TBL` family is very likely irrelevant to audible timing at all (pass 13), and
(b) the actual defect, seen directly on the trig-grid LEDs, is a **sub-step phase
misalignment**, not a step-index error (pass 11) — the switched-to pattern can visibly
land *between* steps, not just on the wrong one.

### Where AR's mechanism has something OT's doesn't

**1. AR has one atomic paired write; OT does not have an equivalent for the analogous
state.** AR's `FUN_4009905c` writes `DAT_40566754 = DAT_40566755 = DAT_405667dc` together,
in the same two instructions, with no other code path able to touch either half
independently (`MECHANISM.md` step 5). OT's `SCALE_IX` bug (fix 2) is a textbook instance
of the *opposite*: `SCALE_IX` and the actual active-pattern pointer are written by
genuinely separate stock code, on separate schedules, and drift apart until a hand-added
hook forces a resync. That the fix for this shape of bug was needed at all confirms OT's
design has no structural guarantee against it — and nothing in passes 4–15 establishes
`SCALE_IX` was the *only* piece of derived per-step state built this way. `REFILL_TBL`
(a per-track quantity, gated by each track's own countdown, `DAT_800065c3`) is a second,
structurally identical candidate: it is computed and committed on its own per-track
schedule, not folded into whatever writes the master step/active-pattern state. AR has
no analogous split — one function, one countdown, one write, for both the pattern pointer
and the step-resume position together.

**2. AR's countdown is a single, shared, step-boundary-quantized gate; OT's derived state
appears to update on multiple, independently-timed schedules.** AR's `FUN_4009905c`
gates *both* halves of the commit (pattern pointer, step-resume position) to land exactly
on the same step/resolution boundary — by construction, a commit can never land mid-step
(`MECHANISM.md` step 4–5). OT, by contrast, appears (per fixes 2 and 3 above) to have at
least three separately-clocked pieces of derived state relevant to a pattern switch: the
master `DAT_800065b6` step-wrap check, `SCALE_IX`, and each track's own `REFILL_TBL`
countdown (`DAT_800065c3`) — each written by its own stock code path, at its own
condition/cadence, not visibly serialized through one shared gate the way AR's two writes
are. A design with several independently-timed writes contributing to the same logical
event is structurally exactly what produces a **sub-step phase** artifact rather than a
clean step-index artifact: if any one of those pieces resolves on a different tick than
the others, the audible result is neither cleanly "right pattern, right step" nor "right
pattern, wrong step" but a misalignment inside a step — which is precisely what OT's LED
test (pass 11) found and precisely the class of defect no purely step-index-arithmetic
fix (all three OT fixes) could ever touch.

**3. A specific, falsifiable candidate this comparison surfaces: does `DAT_800065c3`
(or whatever else feeds `DAT_80001904`'s per-track phase, per `refs/octabam`'s
corroboration) get freshly recomputed/reset at DIRECT JUMP's commit tick, the way AR's
`DAT_405667e8` is recomputed from the *current* tick position on every incoming
request** (never accumulated across requests — `MECHANISM.md` step 3)? If OT's per-track
countdown is instead a running counter that is *not* reset in step with the pattern-pointer
commit, tracks would keep counting on their pre-switch phase after the switch — a
mechanism that would produce exactly the reported symptom shape ("not in time when
switched to," worsening progressively, "generally after they pass step 16" — consistent
with an un-reset counter's drift becoming audible only once it has accumulated enough
ticks past the switch to visibly diverge, or wrap using stale phase). This is a narrow,
directly testable OT-side *measurement* (read whether `DAT_800065c3` and `DAT_80001904`'s
per-track accumulator inputs get touched at the exact commit tick, or drift onward
unreset) — not a patch, and not undertaken this session; it belongs to
`octatrack-kyoti-fw`, not here.

### Status

This closes task step 4 as originally scoped ("read OT's fixes side by side... look
specifically for where OT's implementation might not have an equivalent to the atomic
paired write or the fresh-per-request countdown recompute"): two concrete candidate gaps
were found (no atomic paired write for the `SCALE_IX`/`REFILL_TBL` family; no confirmed
fresh-per-request recompute for the per-track phase state), both consistent with every
unretracted OT-side finding to date (the desync-shaped `SCALE_IX` bug, the LED test's
phase-not-index diagnosis, and three index-exact fixes that didn't move the symptom).
**None of this has been measured against OT's actual disassembly this session** — it is a
structural hypothesis built by comparison, offered to `octatrack-kyoti-fw` as a next
concrete, narrow measurement to run there, not acted on here.

### NEXT for this thread

1. This AR-side investigation's originally-scoped deliverable (task steps 1–4) is now
   complete: mechanism traced end to end and measured (Sessions 1–6), sanity-checked
   (Session 7), written up standalone (`MECHANISM.md`), and compared against OT's fix
   history with concrete candidate gaps identified (this section). Remaining AR-side work
   (TEMP JUMP's revert bookkeeping, the SEQUENTIAL-mode `0x4015716c` write target) is
   explicitly lower priority, per Session 6/7 — pick up only if this thread continues.
2. The natural next step lives in `octatrack-kyoti-fw`, not here: run the falsifiable
   measurement in point 3 above (does OT's per-track phase/countdown state get reset at
   DIRECT JUMP's commit tick, same-track DJ-vs-stock comparison as pass 15 itself already
   recommended). Out of scope for this repo to perform directly.

## Session 8 (2026-09-21) — MAJOR RETRACTION + the finding the OT port actually needed: the commit rebuilds ALL per-track state

Prompted from the OT side. The OT DIRECT JUMP build had just been flashed and produced a
severe regression (frozen transport, audio reduced to clicks) with DIRECT JUMP toggled
**both ON and OFF**, after six successive per-variable "repair" fixes each of which exposed
the next. The user's question was direct: *is AR's DIRECT JUMP actually fully understood?*
Answer: **no.** Sessions 1–7 traced the commit as far as one master scalar and stopped at
`0x4009927c` with the note that `D0` "feeds forward into `0x4009927c`'s onward code (not yet
traced further)". That untraced region is the entire substance of the commit.

The user also supplied a hardware fact that reframed the question: **AR has per-track
sequence lengths** (12 drum tracks + a 13th FX track, each independently settable). So the
hypothesis that AR's simplicity came from a simpler data model was wrong before it was
tested.

### Retracted

- **"AR's commit writes one variable" / "both are properties of a single function with a
  single short countdown" is incomplete to the point of being misleading.** The paired
  pattern write and the `new_step` modulo are the *prologue*. The payload is a rebuild of
  eight parallel per-track arrays.
- The Session 7 framing that offered OT "no atomic paired write for the
  `SCALE_IX`/`REFILL_TBL` family" as the gap was aiming at the wrong level. The gap is not
  that OT fails to write those atomically — it is that OT *adjusts* them at all instead of
  overwriting them wholesale.

### Measured this session (all from `out/fun4009905c_listing.txt`, cross-checked against raw bytes of `out/section_3_MAIN_OS.bin`)

`FUN_4009905c`'s commit, after `DAT_40566754 = DAT_40566755 = target` and
`new_step = masterStep mod patternLen`, runs two unconditional loops over **13 tracks**:

1. `0x400991de`–`0x40099202` — rebuild per-track countdown reloads:
   `*(0x405667c7 + t) = ticksPerStep[ *(track_t + 0x2c7) ] - 1`
2. `0x4009927c`–`0x400992d2` — rebuild per-track phase, five arrays per track:
   `D3 = perTrackScaleMode ? *(track_t + 0x2c5) : patternLen` ; `D2 = new_step mod D3` ;
   then `0x40566720[t] = D2`, `0x4056673a[t] = D2-1`, `0x4056672d[t] = 0`,
   `0x405667ba[t] = -1`, `0x40566830[t] = D2`.

Loop bound `0x2e91` = **exactly** 13 × track stride `0x395` (917) — arithmetic, not
inference. Eight per-track arrays total (see `MECHANISM.md`'s table), each exactly 13
entries, **tiling contiguously**, with four boundaries independently confirmed by the
function's own `cmpa.l` sentinels (`0x40566720`, `0x40566747`, `0x40566782`, `0x405667d4`).
The array geometry is self-proving; nothing here is assumed.

`0x14eb9` is AR's **per-track scale mode flag** — the direct analogue of OT's `SCALE_MODE`
at pattern `+0x8e55`. AR carries OT's per-track scale complexity as well as its per-track
lengths. Its correctness is therefore a property of *how it commits*, not of what it has to
manage.

A second, independently-gated commit site (`0x40099370` onward, gated on `0x405667d6` and
`0x40566748 == 1`) rebuilds `0x405667c7[t]` with byte-identical logic at
`0x400993e8`–`0x40099404`. Two commit paths, one discipline.

### Methodology hazard found (new)

**Ghidra's printed operand order for ColdFire `divsl.l` is unreliable.** It renders
`4c412800` (`0x40099274`) and `4c437802` (`0x400992b6`) with `D2` leading in both, although
`D2` is the quotient/dividend in the first and the remainder in the second. Read the
extension word instead: **field(14:12) = dividend and quotient destination, field(2:0) =
remainder.** Both sites were settled from the encoding and then cross-checked against which
register demonstrably holds the dividend on entry (`D2` ← `mvz.w 0x405666e4` at
`0x40099262`; `D7` ← `move.l D0,D7` at `0x400992b2`), so the conclusion does not rest on the
disassembler at all. Same family as the already-known objdump-garbles-`mvs`/`mvz`/`divsl`
trap; worth carrying to the OT repo, which relies on both tools.

### The invariant, restated (supersedes Session 7's two-property version)

**Rewrite the whole per-track state vector from one master position; never patch it.** No
per-track value survives a commit, so "stale per-track variable" is not a failure mode that
exists on AR. The atomic paired write and the fresh-per-request countdown recompute are
real and still hold, but they are supporting details, not the mechanism.

### NEXT for this thread

AR-side understanding of DIRECT JUMP is now genuinely complete for porting purposes. The
remaining AR questions are unchanged and still low priority (TEMP JUMP's revert
bookkeeping; SEQUENTIAL's `0x4015716c` write target). One new optional item: identify the
semantics of the `0`/`-1` per-track arrays (`0x4056672d`, `0x405667ba`) — the OT port needs
their *analogues* identified on OT, but not necessarily their AR meanings.

The work moves to `octatrack-kyoti-fw`, and the well-posed question there is now:
**enumerate OT's complete per-track state vector** (AR has eight arrays; OT has five known:
`STEP_IN_PAT 0x800064f0`, `TRK_SCALE_IX 0x8000663e`, `REFILL_TBL 0x800064d0`,
`CNTDN_TBL 0x800065c3`, plus MIDI counterparts `0x80006646`/`0x80006508`) by finding every
global written inside stock's own per-track loop, then rebuild all of it in one loop at
commit instead of hooking individual repairs. Note AR's dividend is its **master step
counter** (`0x405666e4`), not an absolute tick — OT's invented `G_ABSTICK` may be
unnecessary; OT's own master `STEP` (`0x800065b6`) is the direct analogue.

## Session 9 (2026-09-22) — AR research consolidated; the OT port landed, and it revealed AR's architecture is the same as OT's

Written from the OT side (`octatrack-kyoti-fw` Session 79 cont.20–31), folded back here at
the user's direction so this repo carries the complete record rather than only the AR half.

### `AR_DIRECT_JUMP.md` (new, canonical, identical in both repos)

Supersedes `MECHANISM.md` as the single document of record. Contains AR's request path,
countdown and commit (both 13-track rebuild loops, full eight-array inventory), the OT
equivalent, a full **AR ↔ OT mapping table**, what the port turned out to be, the 16-bit
bound, AR-side open items, and the methodology hazards. `MECHANISM.md` remains accurate as
corrected in Session 8 but is now the narrower document.

### The finding that reframes this whole repo's purpose

The premise of this project was that AR does something OT does not, which OT should learn.
**That premise is wrong.** OT already contains AR's exact commit architecture: a per-track
rebuild loop (`0x400a4884`–`0x400a49e2`, MIDI twin from `0x400a49e6`) that divides a master
position by each track's own ticks-per-step and wraps it to that track's own length — the
same computation as AR's `0x4009927c`–`0x400992d2`, on the same kind of contiguous per-track
arrays, driven by the same kind of ticks-per-step table.

It was invisible for the entire project because it sits in a **1586-byte region Ghidra never
decoded** (`0x400a4568`–`0x400a4b9a`). OT's DIRECT JUMP never worked not because the machinery
was missing, but because its position input (`0x80006628`, a start offset in master steps) is
0 at a natural boundary and nothing ever set it otherwise.

So the port was: **supply the offset the existing code already expects.** One 6-byte hook.
Measured result — 16 tracks, mixed scales and lengths, armed commit:

| track | scale | len | tps | STEP | derivation |
|-------|-------|-----|-----|------|------------|
| 0, 3–15 | 2 | 16 | 6 | 10 | 156/6 = 26 steps, 26 mod 16 |
| 1 | 0 (2x) | 16 | 3 | 4 | 156/3 = 52 steps, 52 mod 16 |
| 2 | 2 | 12 | 6 | 2 | 26 mod 12 |

Both switch directions 16/16.

### Where AR IS genuinely better — and it is not what Sessions 1–7 thought

Not the atomic write, and not the fresh-per-request countdown, though both are real. It is
**what AR divides**.

AR's dividend is `masterStep mod patternLen` — already bounded. OT's rebuild is fed
`D7 = LEN_TBL[masterScale] * 0x80006628`, and to express "resume where the timeline is" the OT
port must put an *absolute* tick count there. But OT stores the first divide's quotient with
`move.w` (`0x400a4916`) and reads it back **sign-extended** (`mvs.w`, `0x400a4950`), so that
quotient must fit a signed word. Measured by poking the counter: `G_ABSTICK = 40002` gives
`NEXT_STEP = -14` and `STEP = 242` on a 16-step pattern.

Bound ≈ 32767 master steps ≈ **68 minutes of continuous transport** at 120 BPM/16ths. AR never
hits this because it commits from its own per-tick function (`FUN_4009905c`) and can therefore
divide a bounded quantity; OT reuses a pattern-boundary body whose offset input is unbounded.

**That is the one architectural lesson from AR that OT has NOT yet absorbed**, and it is now
the main open problem on the OT side: reducing the absolute counter before it reaches the
loop, with a modulus that preserves every per-track position while keeping the fastest track's
quotient inside a signed word. Those two constraints pull against each other and no
construction covering arbitrary length/scale combinations has been found.

### Corrections to earlier sessions in this repo, carried forward

- Session 8 already retracted "AR's commit writes one variable". Standing.
- Sessions 1–7's "candidate invariant" (atomic write + fresh countdown) is real but
  **secondary**. The primary invariant is *rewrite the whole per-track state vector from one
  master position, never patch it* — and the practical lesson for OT turned out to be the
  boundedness of the dividend, which none of Sessions 1–7 identified.

### Still open here (unchanged, still low priority)

1. TEMP JUMP's revert bookkeeping — inferred to reuse `DAT_40566756`, never checked.
2. SEQUENTIAL's own commit path (`0x4015716c` write target).
3. Semantics of the `0` / `-1` per-track arrays (`0x4056672d`, `0x405667ba`). OT's port does
   not need them; the symmetry is unexplained.

## Session 10 (2026-09-26) — the OT "gold" DIRECT JUMP was never gold; the whole AR engine decompiled in answer

### Why

The OT user re-flashed `GOLD_S87` and reproduced step-fractional playback at **1x, NORMAL
mode, no scales, a plain 16-step ↔ 7-step pattern switch** — the case every V5.x gate had
been measured *against* as the correct baseline. Decision on the OT side: restart the port
from AR's whole sequencer/timing engine, not from the commit loops alone. This session is
that decompilation. Record of the result: **`AR_SEQUENCER_ENGINE.md`** (canonical here,
mirrored into `octatrack-kyoti-fw/reference/`), plus `AR_DIRECT_JUMP.md` §10.

### Method

- `tools/ghidra/GhidraSeqCensus.java` — every instruction touching a list of globals
  (data refs AND bare scalar/cursor operands, so register-indirect loops are not missed),
  then callers/callees of every function that touched one. Built-in table = the sequencer
  globals; script args `name=0xaddr` override it. Two runs: `out/ghidra/seq_census_session10.txt`
  (sequencer state), `timing_census_session10.txt` (timebase, shared region), plus
  `misc_census_session10.txt`.
- `tools/ghidra/GhidraDecompArgs.java` — decompile + raw listing for any list of entry
  addresses; `out/ghidra/seq_decomp_session10.txt` (43 functions, 7720 lines),
  `ui_dispatch_session10.txt`. **Gotcha:** Ghidra prints multi-line `println` output as ONE
  `INFO` line followed by raw continuation lines — a `grep` on the script-name prefix silently
  drops every decompiled body. Filter by stripping the prefix and dropping other modules'
  `INFO/WARN` lines instead.
- Vector table: the image starts at `0x40000400`, the RAM vector table at `0x40000000` is
  built at boot; a regex over `move.l #handler,D0 ; move.l D0,(0x400000xx)` pairs recovers
  every installed handler (12 installs; the three sequencer ones are in `FUN_40097fee`).

### Findings (all measured; details and addresses in AR_SEQUENCER_ENGINE.md)

1. **`FUN_4009905c` is the sequencer tick ISR** (`rte`, INTC0 src 57 level 2). It is a forced
   interrupt: the clock-edge ISR `FUN_40097838` (src 44, level 5) ends with
   `INTFRCH |= 0x2000000`; src 44 itself is forced from the MIDI realtime parser
   `FUN_40080f54` on each `0xF8` when the sync source (`FUN_4009c460` = highest bit of
   `0x4024be38`) is 1. Under internal clock the tick ISR's tail writes a deadline mailbox
   `0x80006838` that no CPU code reads — the clock edge comes from the DSP-shared side.
2. **Time unit**: 1 tick = 1/24 quarter (6 ticks per 1x 16th), kept as `0xdbba0` = 900 000
   sub-units; `now = 0x40566570`. The ISR also runs on quarter-tick slices (`0x36ee8`); every
   musical phase is gated on `0x40566578 == 0`.
3. **The ISR order is the mechanism**: B advance now → D pattern-change commits → E per-track
   trig scheduling (one step of lookahead: event computed at the first tick of a step's
   window, fire time = last tick + microtiming) → F per-track advance → G master advance
   (phase 2: pick next pattern; phase 0: wrap-change) → H fire-countdown landings → I clock
   counters → J timer tail.
4. **The DIRECT JUMP commit (D2) carries no sub-step remainder.** D1 sets `countdown =
   tps_master − master_tick_phase` (next master boundary); D2 rebuilds all 13 tracks
   synchronously (`step = new_step mod len_t`, tick 0, `cntdn = tps_t − 1`, fire countdown
   −1, first-fire mask all set) and writes `master_tick_phase = tps_master − 1` so the master
   step body runs at the end of the same tick. E then fires every track's `new_step`
   immediately (`ahead = 1`) and re-seeds `tick_in_step = tps_t − 1`, F advances, and from
   the next tick on the grid is exact by construction.
5. **The (target step, remainder) pair `0x405667f4/f6` of AR_DIRECT_JUMP §9 is the
   PAUSE / SONG-POSITION mechanism**, written by `FUN_4009a618` (from `FUN_4009a7e8` ← MIDI
   `0xF2`) and `FUN_4009a142` (pause), consumed by transport start `FUN_40098226`
   (`0x40098358`) and the src-44 ISR's deferred landing (`0x40097910`). Not by the jump. So
   OT V5.7–V5.11's `dj_mrem` seed was built on a mis-attribution — withdrawn in §10.
6. **AR's wrap-change path IS OT's boundary body**: `T = cycleStart × tps_master`; per track
   `q = ceil(T/tps_t)` (`0x40566784`), remainder (`0x4056679e`), hold bit when remainder > 0
   (`0x405667b8`, one skipped advance = OT dead end 1), catch-up `cntdn = tps_t −
   tps_master_old` (`0x405667c7`), fire countdown `max(1, tps_master_old + 1 − tps_t)`
   (`0x405667ba`, landing in H). AR never routes a jump through it. OT's port routed *every*
   jump through it (Hook H's `0x80006628` offset into the boundary body) — that is the
   architectural mistake, independent of any later hook.
7. **Neither machine fires trigs from the CPU.** AR posts `(fire time 0x8000aa5c, record
   0x4273c990, slot mask 0x8000681c)` per track and slot into the DSP-shared region, with
   microtiming and swing folded into the fire time and p-locks resolved to a delta list at
   schedule time (`FUN_400989d0`, `FUN_400988fc`). Same shape as OT's `DAT_80001904` table.
8. UI dispatcher `FUN_4003e636`: mode 1 → `FUN_4009a5b0(pat, 1)`, mode 2 → `(pat, 0)`,
   otherwise immediate `FUN_4009a2ae` when stopped; a `view+0xc6` path uses `FUN_4009884c`
   (queued, semantics untraced — open item).

### NEXT

AR side: nothing blocks the port. Open items are listed in AR_SEQUENCER_ENGINE.md §8. The
work moves to the OT repo: measure OT's tick-ISR phase order and its analogues of the
first-fire mask / fire countdown, then build the DJ commit AR's way (§6 of the engine doc) —
never through the boundary body.

## Session 11 (2026-09-27) — AR_DJ_QUIRKS.md: the record of AR DIRECT JUMP behaviours the OT port will eventually deviate from

New file `AR_DJ_QUIRKS.md` (mirrored in the OT repo's `reference/`). Item 1 is a hardware
observation by the user on the AR MKI: NORMAL scale mode, two tracks of 16 and 7 steps,
certain cadences of DIRECT JUMP switches leave the 16-step track exactly half a step off
the grid — stock AR. Mechanism not localised (the DJ commit zeroes every tick phase, so it
arises later; candidates listed in the file as hypotheses). Items 2 and 3 are the
scheduler dedupe duplicate and the master-scale lurch already derived from the decompile.
Rule: the OT port reaches AR-exact behaviour first; deviations come one at a time, each
recorded there with the AR behaviour kept reconstructible.
