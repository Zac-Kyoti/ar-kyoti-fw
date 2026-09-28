# Working in this repository

Reverse-engineering the Analog Rytm firmware to find its own instant/in-time
pattern-switch mechanism ("DIRECT JUMP" — Elektron's own name for it, confirmed in the
firmware strings), with the eventual goal of understanding what makes it correct well
enough to inform `~/Documents/octatrack-kyoti-fw`'s own DIRECT JUMP effort. **That goal is
met (2026-09-27):** the OT shipped DIRECT JUMP V7 — built on the AR-exact port (V6.4) this repo
made possible, then deliberately improved on AR (clock-locked landing; `AR_DJ_QUIRKS.md`).

**Read `NOTES.md` first** — jump to the newest `## Session N`, it's chronological.

## Hard constraints

- **This is a separate repo/history from `~/Documents/octatrack-kyoti-fw`.** Do not merge
  it in or treat it as a subdirectory. Reading that project for methodology is expected;
  copying its content wholesale is not, unless a specific piece is deliberately decided to
  be needed here (its `elektron-firmware-tool` was reused this way; its Ghidra script
  *style* was followed, not copied).
- **Git identity**: `273702472+Zac-Kyoti@users.noreply.github.com` /
  `Zac-Kyoti` — check `git config user.email` before every commit, no exceptions. A real
  name/email must never enter this repo's history (the sibling project had to scrub one
  out after an accidental commit).
- **Hardware = Analog Rytm MKI only. No MKII.** Measured from the `.syx` container's own
  device byte (`0x07` = original Analog Rytm, not `0x0c` = Mk II) and **explicitly
  confirmed by the user** (2026-09-19). Nothing here has touched real hardware yet, and
  nothing should without a fresh explicit go-ahead when that point actually arrives.
- **Never fabricate or hand-edit firmware bytes.** Everything is read from the real
  `.syx`/extracted `.bin`; nothing is invented.
- **This is a CPU/sequencer-side question, not DSP/audio.** Don't go looking at the AR's
  DSP path unless something concretely (not speculatively) points there — the sibling
  project got burned twice chasing that tangent for what turned out to be a pure
  ColdFire-side bug.
- **Scope discipline**: do not start writing OT-side patches, and do not start scoping the
  OT adaptation, until the AR's own mechanism is actually understood (not just its UI-facing
  name/strings). See `NOTES.md` "NEXT" for the current frontier.

## Toolchain quick-reference

- `tools/entropy.py`, `tools/find_base.py` — static recon (see `NOTES.md` Step 1).
- `disasm.sh` — radare2 helper, m68k/ColdFire big-endian, base `0x40000400`.
- `ghidra_project/` (gitignored) — Ghidra 12.1.2, language `68000:BE:32:Coldfire`.
  `analyzeHeadless` needs `JAVA_HOME=/opt/homebrew/opt/openjdk@21` (not on `PATH` by
  default). This Ghidra install has **no Jython and no PyGhidra** — scripts must be Java
  (`tools/ghidra/*.java`, `GhidraScript` subclasses), not `.py`.
- `out/` (gitignored) — extracted binary, entropy/string/pointer analysis outputs, Ghidra
  logs. Elektron-copyrighted material never gets committed (see `.gitignore`).
