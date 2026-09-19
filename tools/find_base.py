#!/usr/bin/env python3
"""Recover a raw firmware image's load base by pointer/string correlation.

Idea: if the image loads at base B, a string at file offset F lives at
virtual address B+F. Absolute 32-bit pointers embedded in the code (immediate
loads, pointer tables) that reference that string will hold exactly B+F.
Sweeping candidate B and counting how many embedded pointers land exactly on
a string start recovers B empirically.

Usage: python3 find_base.py <raw.bin> [--top-byte 0x40] [--min-str 5]
"""
import argparse
import struct
from collections import Counter
from pathlib import Path


def find_strings(data, min_len):
    """Return {offset: text} for printable-ASCII runs of at least min_len."""
    starts = {}
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if 0x20 <= b < 0x7f:
            j = i
            while j < n and 0x20 <= data[j] < 0x7f:
                j += 1
            if j - i >= min_len:
                starts[i] = data[i:j].decode("ascii", "replace")
            i = j
        else:
            i += 1
    return starts


def words_be(data, top_byte):
    """Yield (pos, value) for big-endian 32-bit words at even offsets whose
    high byte == top_byte (candidate pointer region)."""
    for pos in range(0, len(data) - 3, 2):
        if data[pos] == top_byte:
            yield pos, struct.unpack_from(">I", data, pos)[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--top-byte", default="0x40")
    ap.add_argument("--min-str", type=int, default=5)
    ap.add_argument("--csv", help="dump the full ptr->string map to this CSV")
    args = ap.parse_args()
    top = int(args.top_byte, 0)

    data = Path(args.file).read_bytes()
    strings = find_strings(data, args.min_str)
    str_offsets = set(strings)
    print(f"[find_base] {args.file}: {len(data)} bytes, {len(strings)} strings (>= {args.min_str} chars)")
    print(f"[find_base] searching for pointers with high byte {hex(top)} ...")

    candidates = sorted({top << 24} | {(top << 24) + off for off in (0, 0x1000, 0x2000)})
    base_lo = top << 24
    for delta in range(0, 0x20001, 4):
        candidates.append(base_lo + delta)
    candidates = sorted(set(candidates))

    ptrs = list(words_be(data, top))
    ptr_vals = [P for _, P in ptrs]
    ptr_set = set(ptr_vals)
    best = []
    for B in candidates:
        hits = sum(1 for F in str_offsets if (B + F) in ptr_set)
        if hits:
            best.append((hits, B))
    best.sort(reverse=True)

    print("\n[find_base] top candidate bases by strings referenced with an exact pointer:")
    for hits, B in best[:8]:
        print(f"   base 0x{B:08x}  ->  {hits} strings with a direct pointer")

    if not best:
        print("   (no matches; try another --top-byte or check endianness)")
        return

    B = best[0][1]
    print(f"\n[find_base] CHOSEN BASE: 0x{B:08x}")

    matches = [(pos, P, P - B) for pos, P in ptrs if (P - B) in strings]
    print(f"[find_base] {len(matches)} pointers resolve to a string start. Examples:")
    for pos, P, F in matches[:12]:
        s = strings[F][:48].replace("\n", " ")
        print(f"   @0x{pos:06x}: ptr 0x{P:08x} -> file+0x{F:06x} '{s}'")

    if args.csv:
        with open(args.csv, "w") as fh:
            fh.write("ptr_site_vaddr,ptr_value,string_vaddr,file_offset,string\n")
            for pos, P, F in matches:
                s = strings[F].replace('"', '""')
                fh.write(f'0x{B+pos:08x},0x{P:08x},0x{B+F:08x},0x{F:06x},"{s}"\n')
        print(f"[find_base] full map -> {args.csv} ({len(matches)} rows)")


if __name__ == "__main__":
    main()
