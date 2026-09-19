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

### NEXT (for the next session)

1. Look at what `Project::Project()` (`FUN_400af438`) does in the code *after* the main
   sub-object construction block (the several zero-fill loops and the final section
   starting around where `FUN_4016ff30` gets called in a loop) — the mirror-binding pass
   for `Pattern`/`PatternSettings` may live there rather than inside `Pattern::Pattern()`
   itself. This wasn't examined past the point excerpted in this NOTES.md.
2. Alternative approach if (1) doesn't pan out: stop chasing constructors and instead find
   the PTN CHG **setter** directly — go back to `FUN_4003fc14`'s PTN CHG picker block
   (around `0x400407ec`–`0x40040834`) and trace forward past `0x40040834` (not yet done
   carefully) to find the picker's confirm/select callback, the way the case-`0x52` block's
   callback pair (`FUN_4003e0d8`/`FUN_4003eee8`) was spotted by pattern-matching in Session
   2 — that callback, once found, must write *somewhere*, and that somewhere is the answer
   regardless of which C++ sub-object it turns out to be.
3. Once the storage field is genuinely found: confirm by finding the sequencer's reader of
   the same field/offset, and only then assess what makes the real implementation correct
   (task brief step 3's actual deliverable).
4. Do not start on OT adaptation (task step 4) — still not close enough to step 3 being
   solid, three sessions in.

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
