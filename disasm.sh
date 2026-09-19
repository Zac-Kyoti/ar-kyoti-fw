#!/usr/bin/env bash
# Phase 1 helper -- disassembly of the decompressed MAIN OS (ColdFire/m68k BE).
# Usage:
#   ./disasm.sh                 open r2 interactively on the raw image
#   ./disasm.sh strings         dump all strings with offset
#   ./disasm.sh pd 0x1000       run an r2 expr and exit
set -euo pipefail
cd "$(dirname "$0")"

RAW="${RAW:-out/section_3_MAIN_OS.bin}"
[ -f "$RAW" ] || { echo "No $RAW -- extract it with elektron-firmware-tool first." >&2; exit 1; }

# Load base determined empirically (tools/find_base.py): 0x40000400
BASE="${BASE:-0x40000400}"
R2FLAGS=(-a m68k -b 32 -e cfg.bigendian=true -m "$BASE")

case "${1:-}" in
  strings)
    r2 -q "${R2FLAGS[@]}" -c 'e bin.str.raw=true; izz~...' "$RAW" 2>/dev/null || \
      strings -t x -n 6 "$RAW"
    ;;
  "")
    echo "Opening r2 (m68k BE). Useful commands:"
    echo "  aaa            analysis   |  pd 40      disassemble   |  izz  strings"
    echo "  afl            functions  |  s <addr>   seek          |  V    visual mode"
    exec r2 "${R2FLAGS[@]}" "$RAW"
    ;;
  *)
    r2 -q "${R2FLAGS[@]}" -c "$*" "$RAW"
    ;;
esac
