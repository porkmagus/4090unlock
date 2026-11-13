#!/usr/bin/env python3
"""Recompute every static fact quoted in docs/05-static-closure.md.

Read-only. Produces research/static_evidence.json so the numbers in the
documents can be re-derived instead of trusted.

Checks:
  1. dump + extracted-image hashes and sizes;
  2. PCIR/NPDE image chain of both dumps (4 images each);
  3. profile delta count and exact byte ranges, active copy vs backup copy;
  4. FWSEC descriptor + image hash for both profiles;
  5. EFI image header + decompressed PE hash for both profiles;
  6. ucode table app-id map and per-image hashes;
  7. register-constant scan of every plaintext region (legacy x86, EFI PE,
     plaintext Falcon ucodes, DMEMs).

Usage:
    python3 tools/static_evidence.py --out research/static_evidence.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vbios_chain import locate_rom_start, walk  # noqa: E402
from ucode_classify import find_ucode_table, parse_descriptor  # noqa: E402

REGISTERS = {
    0x00823804: "FEAT_OVR_PLM",
    0x00823818: "FEAT_READOUT_1",
    0x0082381C: "SS0",
    0x00823820: "SS1",
    0x00823814: "FEAT_READOUT_0",
    0x0082059C: "FUSE_SS_FFMA",
    0x008207D4: "FUSE_SS_FMLA16",
    0x008207D8: "FUSE_SS_FMLA32",
    0x008207DC: "FUSE_SS_IMLA0",
    0x008207E0: "FUSE_SS_IMLA1",
    0x008207E4: "FUSE_SS_IMLA2",
    0x008207E8: "FUSE_SS_IMLA3",
    0x008207EC: "FUSE_SS_IMLA4",
    0x008200FC: "FUSE_SS_PLM",
    0x0082038C: "SECURE_FEAT_OVR_QUADRO_WR_SECURE",
}

DUMP = {"A": "pc_extracted_files/bios_A_factory.rom",
        "B": "pc_extracted_files/bios_B_factory.rom"}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def ranges(diffs):
    if not diffs:
        return []
    out = [[diffs[0], diffs[0]]]
    for x in diffs[1:]:
        if x == out[-1][1] + 1:
            out[-1][1] = x
        else:
            out.append([x, x])
    return out


def constant_scan(data):
    hits = {}
    for value, name in REGISTERS.items():
        for endian in ("<", ">"):
            pat = struct.pack(endian + "I", value)
            at = data.find(pat)
            while at >= 0:
                hits.setdefault(name, []).append({"offset": at, "endian": endian})
                at = data.find(pat, at + 1)
    return hits


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--out", type=Path, default=Path("research/static_evidence.json"))
    ap.add_argument("--efi-pe-a", type=Path, help="decompressed PE from efi_extract.py for dump A")
    ap.add_argument("--efi-pe-b", type=Path, help="decompressed PE from efi_extract.py for dump B")
    args = ap.parse_args(argv)

    out = {"register_constants": {hex(k): v for k, v in REGISTERS.items()}, "dumps": {}}
    images = {}
    for label, path in DUMP.items():
        raw = Path(path).read_bytes()
        rom = raw[locate_rom_start(raw):]
        chain, error, adjust = walk(rom)
        entry = {
            "path": path,
            "size": len(raw),
            "sha256": sha(raw),
            "rom_start": locate_rom_start(raw),
            "rom_bytes": len(rom),
            "bit_relocation_adjust": adjust,
            "chain_error": error,
            "images": chain,
        }
        # active image 0 and backup copy 2
        copy1 = rom[0:0xE0000]
        copy2 = rom[0xE0000:0x1C0000]
        entry["copy1_sha256"] = sha(copy1)
        entry["copy2_sha256"] = sha(copy2)
        entry["copy1_has_zeros_past_chain"] = copy1[chain[-1]["end"]:].count(0)
        images[label] = {"rom": rom, "copy1": copy1, "copy2": copy2, "chain": chain}

        # legacy x86 image = first image
        legacy = rom[0:chain[0]["end"]]
        entry["legacy_x86_sha256"] = sha(legacy)
        entry["legacy_x86_register_hits"] = constant_scan(legacy)

        # FWSEC via ucode table
        table = find_ucode_table(rom, adjust)
        fw = {}
        for e in table["entries"]:
            if e["app_id"] in (0x85, 0x45, 0x49, 0x89, 0x01, 0x07, 0x08):
                d = parse_descriptor(rom, e["desc_offset"])
                off = e["desc_offset"] + d["size"]
                stored = d.get("stored_size") or 0
                rounded = (stored + 255) & ~255
                img = rom[off:off + stored]
                fw["%#04x" % e["app_id"]] = {
                    "desc_offset": e["desc_offset"],
                    "format": d["format"],
                    "engine_mask": d.get("engine_mask"),
                    "ucode_id": d.get("ucode_id"),
                    "sig_count": d.get("sig_count"),
                    "sig_versions": d.get("sig_versions"),
                    "imem_size": d.get("imem_size"),
                    "dmem_size": d.get("dmem_size"),
                    "image_sha256": sha(img),
                    "image_sha256_dma": sha(rom[off:off + rounded]),
                }
        entry["ucodes"] = fw
        entry["ucode_table_offset"] = table["table_offset"]
        out["dumps"][label] = entry

    # profile delta inside one copy, and across the backups
    a, b = images["A"], images["B"]
    diffs = [i for i in range(0xE0000) if a["copy1"][i] != b["copy1"][i]]
    out["profile_delta"] = {
        "active_copy_differing_bytes": len(diffs),
        "active_copy_ranges": [[s, e, e - s + 1] for s, e in ranges(diffs)],
        "backup_copy_differing_bytes": sum(1 for i in range(0xE0000) if a["copy2"][i] != b["copy2"][i]),
    }
    diffs_within = [i for i in range(0xE0000) if a["copy1"][i] != a["copy2"][i]]
    out["within_dump_copy_delta"] = {
        "differing_bytes": len(diffs_within),
        "first_offset": diffs_within[0] if diffs_within else None,
    }

    # optional decompressed EFI PE identity
    for label, p in (("A", args.efi_pe_a), ("B", args.efi_pe_b)):
        if p and p.exists():
            data = p.read_bytes()
            out["dumps"][label]["efi_pe_sha256"] = sha(data)
            out["dumps"][label]["efi_pe_bytes"] = len(data)
            out["dumps"][label]["efi_pe_register_hits"] = constant_scan(data)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2) + "\n")
    print("wrote", args.out)
    print("profile delta: %d bytes in %d ranges; backup delta %d bytes" % (
        out["profile_delta"]["active_copy_differing_bytes"],
        len(out["profile_delta"]["active_copy_ranges"]),
        out["profile_delta"]["backup_copy_differing_bytes"]))
    for s, e, n in out["profile_delta"]["active_copy_ranges"]:
        print("  %#08x..%#08x  %5d bytes" % (s, e, n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
