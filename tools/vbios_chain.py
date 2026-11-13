#!/usr/bin/env python3
"""Walk an NVIDIA VBIOS dump into its option-ROM images.

Read-only. No hardware, no writes to firmware.

Why this exists: the two on-card dumps in ``pc_extracted_files/`` are not bare
option ROMs. Each is an ``NVGI`` container holding a full VBIOS image, whose
first bytes are an option-ROM header followed by a *chain* of images
(PC-AT, EFI, NVIDIA 0xE0 extensions). The chain is not the PCI spec's simple
"AA55 + size" walk:

  * NVGI-wrapped dumps start with a 0x9400-byte header that has no AA55 at 0;
  * images may be signed with 0xAA55, 0x4E56 ("VN") or 0xBB77;
  * the data structure may be PCIR, NPDS or RGIS;
  * an NVIDIA PCI Data Extension ("NPDE") immediately after the data
    structure overrides the image length (SUBIMAGE_LEN at NPDE+8, 512-byte
    units) and can override the "last image" indicator (NPDE+10, bit 7).

Those rules are the ones the public unlock module implements in
``gpu-unlock-ada/kernel/gpu_unlock/vbios_610.c:expansion()``; this tool is a
faithful re-implementation and is cross-checked against it (same image start
offsets, same lengths, same closing image).

Usage:
    python3 tools/vbios_chain.py pc_extracted_files/bios_A_factory.rom
    python3 tools/vbios_chain.py DUMP --json out.json --extract /tmp/imgs
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

IMAGE_SIGNATURES = (0xAA55, 0x4E56, 0xBB77)
DATA_SIGNATURES = (0x52494350, 0x5344504E, 0x53494752)  # PCIR, NPDS, RGIS
NPDE = 0x4544504E  # "NPDE" little-endian


def u16(b, at):
    return struct.unpack_from("<H", b, at)[0]


def u32(b, at):
    return struct.unpack_from("<I", b, at)[0]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def locate_rom_start(raw):
    """Return the offset of the option-ROM header inside a dump.

    NVGI dumps put the ROM at 0x9400. Accept either the literal NVGI header or
    any 0x200-aligned 0xAA55 whose +0x18 pointer resolves to a real data
    structure signature.
    """
    if raw[:4] == b"NVGI":
        for off in range(0, min(len(raw), 0x20000) - 0x1A, 0x200):
            if u16(raw, off) == 0xAA55 and _plausible(raw, off):
                return off
        raise ValueError("NVGI container without a resolvable option ROM")
    if _plausible(raw, 0):
        return 0
    for off in range(0, min(len(raw), 0x100000) - 0x1A, 0x200):
        if u16(raw, off) == 0xAA55 and _plausible(raw, off):
            return off
    raise ValueError("no option-ROM header found")


def _plausible(raw, off):
    if off + 0x1A > len(raw):
        return False
    p = off + u16(raw, off + 0x18)
    return 0 <= p and p + 4 <= len(raw) and u32(raw, p) in DATA_SIGNATURES


def walk(rom):
    """Walk the image chain. Returns (images, error_reason_or_None)."""
    images = []
    pos = 0
    base_len = 0
    ext_pos = 0
    for _ in range(16):
        if pos + 0x1A > len(rom):
            return images, "image header past end of ROM", 0
        sig = u16(rom, pos)
        if sig not in IMAGE_SIGNATURES:
            return images, "no AA55/VN/BB77 image signature at %#x" % pos, 0
        pcir = pos + u16(rom, pos + 0x18)
        if pcir + 0x16 > len(rom):
            return images, "data structure past end of ROM", 0
        dsig = u32(rom, pcir)
        if dsig not in DATA_SIGNATURES:
            return images, "data signature %#x at %#x is not PCIR/NPDS/RGIS" % (dsig, pcir), 0
        slen = u16(rom, pcir + 0x0A)
        length = u16(rom, pcir + 0x10) * 512
        code_type = rom[pcir + 0x14]
        last = bool(rom[pcir + 0x15] & 0x80)
        npde_at = (pcir + slen + 0x0F) & ~0x0F
        npde = None
        if npde_at + 4 <= len(rom) and u32(rom, npde_at) == NPDE:
            rev = u16(rom, npde_at + 4)
            hdr_len = u16(rom, npde_at + 6)
            sub_blocks = u16(rom, npde_at + 8)
            npde = {
                "offset": npde_at,
                "revision": "%d.%d" % (rev >> 8, rev & 0xFF),
                "header_len": hdr_len,
                "subimage_blocks": sub_blocks,
            }
            if rev in (0x100, 0x101) and hdr_len >= 10 and npde_at + hdr_len <= len(rom):
                length = sub_blocks * 512
                if hdr_len > 10:
                    last = bool(rom[npde_at + 10] & 0x80)
                    npde["last_override"] = last
        if not length or pos + length > len(rom):
            return images, "image at %#x has invalid length %#x" % (pos, length), 0
        if not base_len and code_type == 0x00:
            base_len = length
        if not ext_pos and code_type == 0xE0:
            ext_pos = pos
        blob = rom[pos:pos + length]
        images.append({
            "start": pos,
            "length": length,
            "end": pos + length,
            "code_type": code_type,
            "last": last,
            "signature": "0x%04X" % sig,
            "data_signature": rom[pcir:pcir + 4].decode("latin-1"),
            "sha256": sha256(blob),
            "npde": npde,
        })
        if last:
            break
        pos += length
    # "adjust" is the relocation the BIT-table pointers in image 0 need: they
    # are stored as if the first 0xE0 extension directly followed the first
    # (PC-AT) image. See vbios_610.c:expansion().
    adjust = ext_pos - base_len if ext_pos and base_len and ext_pos >= base_len else 0
    return images, None, adjust


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("dump", type=Path, help="NVGI dump or bare option ROM")
    ap.add_argument("--json", type=Path, help="write full result as JSON")
    ap.add_argument("--extract", type=Path, help="write each image into this directory")
    args = ap.parse_args(argv)

    raw = args.dump.read_bytes()
    start = locate_rom_start(raw)
    rom = raw[start:]
    images, error, adjust = walk(rom)

    out = {
        "file": str(args.dump),
        "file_size": len(raw),
        "file_sha256": sha256(raw),
        "rom_start": start,
        "rom_length": len(rom),
        "rom_sha256": sha256(rom),
        "bit_relocation_adjust": adjust,
        "chain_error": error,
        "images": images,
    }
    print("%s  (%d bytes, sha256 %s)" % (args.dump, len(raw), out["file_sha256"][:16]))
    print("ROM start %#x, %d bytes; BIT relocation adjust = %#x" % (start, len(rom), adjust))
    print()
    print("%-10s %-10s %-6s %-5s %-4s %-9s %s" %
          ("start", "end", "type", "last", "npde", "length", "sha256"))
    for im in images:
        print("%#010x %#010x %#06x %-5s %-4s %#9x %s" % (
            im["start"], im["end"], im["code_type"],
            "yes" if im["last"] else "no",
            "yes" if im["npde"] else "no",
            im["length"], im["sha256"][:16]))
    if error:
        print("\nchain stopped: %s" % error)

    if args.extract:
        args.extract.mkdir(parents=True, exist_ok=True)
        for im in images:
            name = "image_%02x_%06x.bin" % (im["code_type"], im["start"])
            (args.extract / name).write_bytes(rom[im["start"]:im["end"]])
            print("wrote", args.extract / name)

    if args.json:
        args.json.write_text(json.dumps(out, indent=2) + "\n")
        print("wrote", args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
