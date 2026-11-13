#!/usr/bin/env python3
"""Classify the Falcon ucode entries of an NVIDIA VBIOS ROM from their metadata.

Read-only. Answers, for every entry in the FALCON_UCODE table: what does the
*descriptor* say it is (app id, engine mask, ucode id, sizes, signatures), what
does the DMEM say (plaintext interface header, build stamp, embedded strings),
and is the IMEM plaintext or ciphertext (entropy / zero rate)?

Why metadata and not entropy alone: an encrypted region and a compressed one
both look random. The only safe classification order is
  1. structure (BIT header -> token 0x70 -> ucode table -> descriptor),
  2. descriptor fields (app id, engine mask, ucode id, signature count),
  3. plaintext DMEM contents (interface header, build date, strings),
  4. entropy, used only to say "this region is not plaintext code".

Descriptor layouts (FALCON_UCODE_DESC_V1/V2/V3), cross-checked against
nv-uefi-unlocker assets/src/vbios.rs:
  vDesc dword: bit0 = header present, bit2 = encrypted, [15:8] = version,
               [31:16] = descriptor size
  V1 (40 B, Pascal-) : stored@4 uncompressed@8 entry@12 imem_base@16
                       imem_load@20 ... dmem_base@32 dmem_load@36
  V2 (60 B, Turing)  : as V1 + interface_offset@16, and dmem_* shift to 44/48
  V3 (44 B, GA10x+)  : stored@4 pkc@8 interface@12 imem_base@16 imem_load@20
                       imem_virt@24 dmem_base@28 dmem_load@32 engine_mask@36
                       ucode_id@38 sig_count@39 sig_versions@40
Some pre-Turing entries carry no vDesc at all (the first dword is the stored
size); those are reported as "legacy" with the raw header dumped.

Usage:
    python3 tools/ucode_classify.py DUMP --json research/ucode_A.json --outdir out/
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vbios_chain import locate_rom_start, walk  # noqa: E402

APP_IDS = {
    0x01: "PRE_OS",
    0x05: "FIRMWARE_SEC_LIC",
    0x08: "LS_UDE",
    0x45: "FWSEC_DBG (0x05|0x40)",
    0x85: "FWSEC_PROD (0x05|0x80)",
    0x49: "app 0x09 DBG (0x09|0x40)",
    0x89: "app 0x09 PROD (0x09|0x80)",
    0x07: "app 0x07",
}


def u8(b, o):
    return b[o]


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def entropy(data):
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = float(len(data))
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def find_bit_header(rom):
    """First vendored BIT header: FF B8 'BIT\\0' whose bytes sum to 0 mod 256."""
    for at in range(0, len(rom) - 12):
        if u16(rom, at) == 0xB8FF and rom[at + 2:at + 6] == b"BIT\x00":
            size = rom[at + 8]
            if size >= 12 and (sum(rom[at:at + size]) & 0xFF) == 0:
                return at
    raise ValueError("no BIT header found")


def find_ucode_table(rom, adjust):
    bit = find_bit_header(rom)
    header_size = u8(rom, bit + 8)
    token_size = u8(rom, bit + 9)
    token_count = u8(rom, bit + 10)
    for i in range(token_count):
        t = bit + header_size + i * token_size
        if u8(rom, t) != 0x70 or u8(rom, t + 1) != 2:
            continue
        ptr = u32(rom, t + 4) if token_size >= 8 else u16(rom, t + 4)
        table = adjust + u32(rom, ptr)
        if u8(rom, table) != 1:
            continue
        hdr_size, entry_size, count = u8(rom, table + 1), u8(rom, table + 2), u8(rom, table + 3)
        entries = []
        for e in range(count):
            at = table + hdr_size + e * entry_size
            entries.append({
                "index": e,
                "app_id": u8(rom, at),
                "target_id": u8(rom, at + 1),
                "desc_pointer": u32(rom, at + 2),
                "desc_offset": adjust + u32(rom, at + 2),
            })
        return {"bit_offset": bit, "bit_size": u8(rom, bit + 8), "stride": token_size,
                "table_offset": table, "table_header": {"version": u8(rom, table),
                                                        "header_size": hdr_size,
                                                        "entry_size": entry_size,
                                                        "count": count},
                "entries": entries}
    raise ValueError("no 0x70/2 token with a valid ucode table")


def parse_descriptor(rom, at):
    vdesc = u32(rom, at)
    version = (vdesc >> 8) & 0xFF
    size = (vdesc >> 16) & 0xFFFF
    out = {"vdesc": "0x%08X" % vdesc, "version": version, "size": size,
           "header_present": bool(vdesc & 1), "encrypted_bit": bool(vdesc & 4)}
    if version == 3 and size >= 44:
        out.update({
            "format": "V3",
            "stored_size": u32(rom, at + 4),
            "pkc_offset": u32(rom, at + 8),
            "interface_offset": u32(rom, at + 12),
            "imem_phys_base": u32(rom, at + 16),
            "imem_size": u32(rom, at + 20),
            "imem_virt_base": u32(rom, at + 24),
            "dmem_phys_base": u32(rom, at + 28),
            "dmem_size": u32(rom, at + 32),
            "engine_mask": u16(rom, at + 36),
            "ucode_id": u8(rom, at + 38),
            "sig_count": u8(rom, at + 39),
            "sig_versions": u16(rom, at + 40),
        })
        out["signature_bytes"] = size - 44
    elif version == 2 and size >= 60:
        out.update({
            "format": "V2",
            "stored_size": u32(rom, at + 4),
            "uncompressed_size": u32(rom, at + 8),
            "virtual_entry": u32(rom, at + 12),
            "interface_offset": u32(rom, at + 16),
            "imem_phys_base": u32(rom, at + 20),
            "imem_size": u32(rom, at + 24),
            "imem_virt_base": u32(rom, at + 28),
            "imem_sec_base": u32(rom, at + 32),
            "imem_sec_size": u32(rom, at + 36),
            "dmem_offset": u32(rom, at + 40),
            "dmem_phys_base": u32(rom, at + 44),
            "dmem_size": u32(rom, at + 48),
        })
    elif version == 1 and size >= 40:
        out.update({
            "format": "V1",
            "stored_size": u32(rom, at + 4),
            "uncompressed_size": u32(rom, at + 8),
            "virtual_entry": u32(rom, at + 12),
            "imem_phys_base": u32(rom, at + 16),
            "imem_size": u32(rom, at + 20),
            "dmem_phys_base": u32(rom, at + 32),
            "dmem_size": u32(rom, at + 36),
        })
    else:
        # No vDesc: pre-Turing layout, first words are sizes. Detect the
        # descriptor length by requiring stored == imem + dmem and the header
        # to be 60 or 64 bytes (observed 60).
        out["format"] = "legacy"
        stored = u32(rom, at)
        imem = u32(rom, at + 20)
        dmem = u32(rom, at + 44)
        out.update({"stored_size": stored, "imem_size": imem, "dmem_size": dmem,
                    "uncompressed_size": u32(rom, at + 4), "interface_offset": u32(rom, at + 16)})
        for cand in (60, 64):
            if stored == imem + dmem and imem and dmem:
                out["size"] = cand
                break
    return out


def describe_image(rom, at, desc, outdir, tag):
    off = at + desc["size"]
    stored = desc.get("stored_size") or 0
    imem = desc.get("imem_size") or 0
    dmem = desc.get("dmem_size") or 0
    if not stored or off + stored > len(rom):
        return {"error": "image out of range", "image_offset": off, "stored_size": stored}
    img = rom[off:off + stored]
    # The public unlock module rounds the stored size up to 256 bytes for DMA
    # (vbios_610.c descriptor()); hashes quoted from that path are over the
    # rounded span. Record both so either convention is reproducible.
    rounded = (stored + 255) & ~255
    body = {
        "image_offset": off,
        "image_size": stored,
        "dma_size": rounded,
        "image_sha256": sha256(img),
        "image_sha256_dma": sha256(rom[off:off + rounded]),
        "declared_imem_dmem_sum": imem + dmem,
        "sizes_consistent": (imem + dmem) == stored,
    }
    im = img[:imem] if imem else img
    dm = img[imem:imem + dmem] if dmem else b""
    body["imem"] = {"size": len(im), "entropy": round(entropy(im), 3),
                    "zero_percent": round(100.0 * im.count(0) / max(1, len(im)), 1)}
    if dm:
        body["dmem"] = {"size": len(dm), "entropy": round(entropy(dm), 3),
                        "zero_percent": round(100.0 * dm.count(0) / max(1, len(dm)), 1)}
        iface = desc.get("interface_offset") or 0
        if iface + 4 <= len(dm):
            body["dmem"]["interface_header"] = {
                "offset": iface,
                "bytes": dm[iface:iface + 4].hex(" "),
                "version": dm[iface],
                "header_size": dm[iface + 1],
                "stride": dm[iface + 2],
                "entries": dm[iface + 3],
            }
        body["dmem"]["strings"] = [m.group().decode("latin-1")
                                   for m in re.finditer(rb"[ -~]{5,}", dm)][:24]
        body["dmem"]["head_hex"] = dm[:48].hex(" ")
    if outdir:
        outdir.mkdir(parents=True, exist_ok=True)
        p = outdir / ("ucode_%s.bin" % tag)
        p.write_bytes(img)
        body["path"] = str(p)
        if dm:
            d = outdir / ("ucode_%s.dmem.bin" % tag)
            d.write_bytes(dm)
            body["dmem"]["path"] = str(d)
            i = outdir / ("ucode_%s.imem.bin" % tag)
            i.write_bytes(im)
            body["imem"]["path"] = str(i)
    return body


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("dump", type=Path)
    ap.add_argument("--json", type=Path)
    ap.add_argument("--outdir", type=Path)
    args = ap.parse_args(argv)

    raw = args.dump.read_bytes()
    rom = raw[locate_rom_start(raw):]
    _, _, adjust = walk(rom)
    table = find_ucode_table(rom, adjust)

    result = {"file": str(args.dump), "file_sha256": sha256(raw),
              "bit_relocation_adjust": adjust, "ucode_table": table, "ucodes": []}
    print("%s: BIT@%#x, ucode table@%#x (%d entries, stride %d)" % (
        args.dump.name, table["bit_offset"], table["table_offset"],
        table["table_header"]["count"], table["table_header"]["entry_size"]))
    print()
    print("%-3s %-6s %-34s %-6s %-8s %-9s %-7s %s" %
          ("#", "app", "name", "engine", "imem/dmem", "sigs", "entropy", "sha256"))
    for e in table["entries"]:
        if e["app_id"] == 0:
            continue
        desc = parse_descriptor(rom, e["desc_offset"])
        tag = "%02x_%06x" % (e["app_id"], e["desc_offset"])
        body = describe_image(rom, e["desc_offset"], desc, args.outdir, tag)
        entry = dict(e)
        entry["app_name"] = APP_IDS.get(e["app_id"], "unknown")
        entry["descriptor"] = desc
        entry["image"] = body
        result["ucodes"].append(entry)
        imem = body.get("imem", {})
        print("%-3d %#06x %-34s %-6s %5s/%-5s %-7s %-7s %s" % (
            e["index"], e["app_id"], entry["app_name"],
            "%#x" % desc["engine_mask"] if "engine_mask" in desc else "-",
            imem.get("size"), body.get("dmem", {}).get("size"),
            "%d/%#x" % (desc.get("sig_count", 0), desc.get("sig_versions", 0)),
            imem.get("entropy"), body.get("image_sha256", "")[:16]))
        if body.get("dmem", {}).get("interface_header"):
            h = body["dmem"]["interface_header"]
            print("      DMEM interface @%d: %s (ver %d hdr %d stride %d entries %d)" % (
                h["offset"], h["bytes"], h["version"], h["header_size"], h["stride"], h["entries"]))
        if body.get("dmem", {}).get("strings"):
            print("      DMEM strings: %s" % "; ".join(body["dmem"]["strings"][:8]))
        if desc["format"] == "legacy":
            print("      legacy header (no vDesc): %s" % rom[e["desc_offset"]:e["desc_offset"] + 60].hex(" "))

    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n")
        print("\nwrote", args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
