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

### NEXT (for the next session)

Top-down from the UI (start at the picker, read forward) has hit diminishing returns —
`FUN_4003fc14` is a large multi-feature dispatcher with unreliable decompilation, and two
plausible-looking leads inside it (a jump-table dispatch, `FUN_40137440` as a mode getter)
were both checked and ruled out this session. A different, more structural approach is
likely to pay off better next session:

1. **Try bottom-up instead of top-down**: rather than reading forward from the UI picker,
   look for the *sequencer's* pattern-boundary check directly — by analogy to how the OT
   project originally found its own per-tick engine (`FUN_400a1eea`), not by re-deriving
   it from a menu handler. Candidate entry points: the `SequencerStates` singleton's
   accessor (`getInstance()`-style lazy-init function, findable from its one string xref at
   `0x4003535e`) and its class layout; or search for the actual `Pattern::updateMirror` /
   `PatternSettings::updateMirror` **function bodies** (not their RTTI registration sites
   found this session) via vtable-slot tracing from a `Pattern`/`PatternSettings` instance,
   since the registration code at `0x400a8a70`+ runs at startup and likely constructs a
   vtable-bearing object nearby.
2. Once the pattern-switch commit path is found: identify where it reads the 4-valued mode
   (SEQUENTIAL/DIRECT START/DIRECT JUMP/TEMP JUMP) and how it stays correct — the ordering/
   locking/state-consistency invariants are the actual deliverable this project exists to
   produce (task brief step 3).
3. Do not start on OT adaptation (step 4) before step 3 is solid.
4. **Process note**: when the decompiler output looks structurally implausible (bogus
   stack-var aliasing, calls with no visible args), stop and re-derive from raw
   disassembly rather than reasoning from the pseudo-C — exactly the trap OT's own Session
   70 passes 4–14 fell into before pass 15 retracted them.
