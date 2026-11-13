#!/usr/bin/env python3
"""Extract the FWSEC descriptor and firmware image from an NVIDIA VBIOS ROM.

Port of gpu-unlock-ada/kernel/gpu_unlock/vbios_610.c (GPL-2.0) — same bounds
checks, same field meanings, no firmware-owned pointer trusted as a host
pointer. Read-only.

Outputs a JSON descriptor and the raw FWSEC image (IMEM followed by DMEM).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


def r16(b, at): return struct.unpack_from("<H", b, at)[0]
def r32(b, at): return struct.unpack_from("<I", b, at)[0]


def rom_signature(sig): return sig in (0xAA55, 0x4E56, 0xBB77)
def data_signature(sig): return sig in (0x52494350, 0x5344504E, 0x53494752)


def expansion(rom: bytes):
    """Walk the option-ROM chain; return (adjust, parts)."""
    if len(rom) < 2 or not rom_signature(r16(rom, 0)):
        raise ValueError("not an option ROM (no AA55/VN/w BB77 signature)")
    pos = 0
    base = ext = 0
    parts = []
    for _ in range(8):
        if pos + 0x1A > len(rom) or not rom_signature(r16(rom, pos)):
            raise ValueError(f"bad image signature at {pos:#x}")
        pcir = pos + r16(rom, pos + 0x18)
        if pcir + 0x16 > len(rom):
            raise ValueError("PCIR out of range")
        if not data_signature(r32(rom, pcir)):
            raise ValueError(f"bad PCIR data signature at {pcir:#x}")
        nbytes = r16(rom, pcir + 0x10) * 512
        last = rom[pcir + 0x15] & 0x80
        npde = (pcir + r16(rom, pcir + 0x0A) + 15) & ~15
        if npde + 4 <= len(rom) and r32(rom, npde) == 0x4544504E:  # 'NPDE'
            ext_rev = r16(rom, npde + 4)
            ext_len = r16(rom, npde + 6)
            if ext_rev in (0x100, 0x101):
                sub = r16(rom, npde + 8) * 512
                if ext_len < 10 or npde + ext_len > len(rom):
                    raise ValueError("NPDE out of range")
                if ext_len > 10:
                    last = rom[npde + 10] & 0x80
                elif sub < nbytes:
                    last = 0
                nbytes = sub
        parts.append(dict(pos=pos, pcir=pcir, bytes=nbytes,
                          code_type=rom[pcir + 0x14], last=bool(last)))
        if not nbytes or pos + nbytes > len(rom):
            raise ValueError("image length out of range")
        if not base and rom[pcir + 0x14] == 0:
            base = nbytes
        if not ext and rom[pcir + 0x14] == 0xE0:
            ext = pos
        if last:
            break
        pos += nbytes
    if ext and base and ext < base:
        raise ValueError("extension image precedes base image")
    return (ext - base if ext and base else 0), parts


def find_bit(rom: bytes):
    """Yield (offset, header_size, stride, tokens, ucode_table_ptr)."""
    at = 0
    while True:
        at = rom.find(b"\xff\xb8BIT", at)
        if at < 0:
            return
        if at + 12 > len(rom):
            return
        hsize, stride, tokens = rom[at + 8], rom[at + 9], rom[at + 10]
        if hsize < 12 or stride < 6 or at + hsize > len(rom):
            at += 1
            continue
        if sum(rom[at:at + hsize]) & 0xFF:
            at += 1
            continue
        if at + hsize + tokens * stride > len(rom):
            at += 1
            continue
        for i in range(tokens):
            tok = at + hsize + i * stride
            if rom[tok] == 0x70 and rom[tok + 1] == 2 and r16(rom, tok + 2) >= 4:
                ptr = r32(rom, tok + 4) if stride >= 8 else r16(rom, tok + 4)
                if ptr and ptr + 4 <= len(rom):
                    yield at, hsize, stride, tokens, ptr
        at += 1


def ucode_entries(rom: bytes, ptr: int, adjust: int):
    table = adjust + r32(rom, ptr)
    if table + 6 > len(rom):
        return None
    ver, hdr, stride, count = rom[table], rom[table + 1], rom[table + 2], rom[table + 3]
    out = dict(table=table, version=ver, header=hdr, stride=stride, count=count, entries=[])
    if ver != 1 or hdr < 6 or stride < 6:
        return out
    for j in range(count):
        e = table + hdr + j * stride
        if e + 6 > len(rom):
            break
        out["entries"].append(dict(index=j, type=e and rom[e],
                                   version=rom[e + 1],
                                   length=r16(rom, e + 4) if stride >= 8 else None,
                                   offset=r32(rom, e + 2)))
    return out


def descriptor(rom: bytes, off: int):
    hdr = r32(rom, off)
    size = hdr >> 16
    if not (hdr & 1) or ((hdr >> 8) & 0xFF) != 3 or size < 44:
        raise ValueError(f"unsupported FWSEC descriptor at {off:#x}: {hdr:#x}")
    if off + size > len(rom):
        raise ValueError("descriptor out of range")
    stored = r32(rom, off + 4)
    image_size = (stored + 255) & ~255
    if off + size + image_size > len(rom):
        raise ValueError("FWSEC image out of range")
    fw = dict(
        descriptor_offset=off, descriptor_size=size, header=hdr,
        stored_size=stored, image_offset=off + size, image_size=image_size,
        pkc_off=r32(rom, off + 8), interface_off=r32(rom, off + 12),
        imem_pa=r32(rom, off + 16), imem_size=r32(rom, off + 20),
        imem_va=r32(rom, off + 24), dmem_pa=r32(rom, off + 28),
        dmem_size=r32(rom, off + 32), engine_mask=r16(rom, off + 36),
        ucode_id=rom[off + 38], sig_count=rom[off + 39],
        sig_versions=r16(rom, off + 40),
        sig_offset=off + 44, sig_bytes=size - 44,
    )
    fw["data_offset"] = fw["imem_size"]
    return fw


def extract(path: Path):
    rom = path.read_bytes()
    adjust, parts = expansion(rom)
    found = []
    for bit, hsize, stride, tokens, ptr in find_bit(rom):
        u = ucode_entries(rom, ptr, adjust)
        if not u:
            continue
        for e in u["entries"]:
            if e["type"] == 0x85:
                d = descriptor(rom, adjust + e["offset"])
                d["bit_offset"] = bit
                d["ucode_table"] = u
                found.append(d)
    if not found:
        raise SystemExit(f"{path}: no FWSEC descriptor found")
    best = found[0]
    img = rom[best["image_offset"]:best["image_offset"] + best["image_size"]]
    best["image_sha256"] = hashlib.sha256(img).hexdigest()
    best["rom_sha256"] = hashlib.sha256(rom).hexdigest()
    best["rom_bytes"] = len(rom)
    best["adjust"] = adjust
    best["parts"] = parts
    return best, img


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("rom", type=Path)
    ap.add_argument("--out", type=Path, default=Path("."))
    args = ap.parse_args()
    fw, img = extract(args.rom)
    args.out.mkdir(parents=True, exist_ok=True)
    stem = args.rom.stem
    (args.out / f"{stem}.fwsec.json").write_text(json.dumps(fw, indent=2))
    (args.out / f"{stem}.fwsec.bin").write_bytes(img)
    print(json.dumps({k: v for k, v in fw.items() if k not in ("parts", "ucode_table")}, indent=2))
    print("ucode table:", {k: v for k, v in fw["ucode_table"].items() if k != "entries"})
    print("entries:", [(hex(e['type']), e['version']) for e in fw["ucode_table"]["entries"]])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
