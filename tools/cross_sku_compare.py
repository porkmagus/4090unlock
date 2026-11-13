#!/usr/bin/env python3
"""Compare the firmware payloads of two NVIDIA VBIOS dumps, entry by entry.

This is the cross-SKU test from docs/06: if the same authenticated firmware runs
on two SKUs that have different tensor rates, the rate cannot be coming from
that firmware.

For every populated FALCON_UCODE entry it reports:
  * descriptor equality (sizes, engine mask, ucode id, signature count/versions)
  * IMEM byte-identity and diff count
  * DMEM byte-identity, diff count and the differing offsets
  * SHA-256 of each image and of the DMEM

An IMEM diff count of 0 is strong: the IMEM is AES ciphertext on the signed
entries, so identical ciphertext means the same key, the same IV and the same
plaintext. A non-zero DMEM diff in the low tens of bytes is the per-SKU
parameter block.

Usage:
    python3 tools/cross_sku_compare.py ROM_A ROM_B --json research/cross_sku_firmware.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vbios_chain import locate_rom_start, walk  # noqa: E402
from ucode_classify import find_ucode_table, parse_descriptor  # noqa: E402

APP_NAMES = {
    0x01: "PRE_OS", 0x07: "app 0x07", 0x08: "LS_UDE",
    0x45: "FWSEC_DBG", 0x85: "FWSEC_PROD",
    0x49: "app 0x09 DBG", 0x89: "app 0x09 PROD",
}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def load(path):
    raw = Path(path).read_bytes()
    rom = raw[locate_rom_start(raw):]
    _, error, adjust = walk(rom)
    table = find_ucode_table(rom, adjust)
    images = {}
    for e in table["entries"]:
        if e["app_id"] == 0:
            continue
        d = parse_descriptor(rom, e["desc_offset"])
        off = e["desc_offset"] + d["size"]
        img = rom[off:off + (d.get("stored_size") or 0)]
        imem = img[:d.get("imem_size") or 0]
        dmem = img[(d.get("imem_size") or 0):(d.get("imem_size") or 0) + (d.get("dmem_size") or 0)]
        images[e["app_id"]] = {
            "desc_offset": e["desc_offset"],
            "descriptor": d,
            "image_sha256": sha(img),
            "image_sha256_dma": sha(rom[off:off + ((len(img) + 255) & ~255)]),
            "imem": imem,
            "dmem": dmem,
            "imem_sha256": sha(imem),
            "dmem_sha256": sha(dmem),
        }
    return {
        "path": str(path), "file_sha256": sha(raw), "rom_bytes": len(rom),
        "bit_relocation_adjust": adjust, "chain_error": error,
        "ucode_table_offset": table["table_offset"], "images": images,
    }


def compare(a, b):
    out = []
    for app in sorted(set(a["images"]) | set(b["images"])):
        ia, ib = a["images"].get(app), b["images"].get(app)
        row = {"app_id": app, "app_name": APP_NAMES.get(app, "unknown")}
        if not ia or not ib:
            row["status"] = "only in one dump"
            out.append(row)
            continue
        imem_diffs = [i for i in range(min(len(ia["imem"]), len(ib["imem"])))
                      if ia["imem"][i] != ib["imem"][i]]
        dmem_diffs = [i for i in range(min(len(ia["dmem"]), len(ib["dmem"])))
                      if ia["dmem"][i] != ib["dmem"][i]]
        row.update({
            "descriptor_identical": ia["descriptor"] == ib["descriptor"],
            "engine_mask": ia["descriptor"].get("engine_mask"),
            "ucode_id": ia["descriptor"].get("ucode_id"),
            "signature_count": ia["descriptor"].get("sig_count"),
            "signature_versions": ia["descriptor"].get("sig_versions"),
            "imem_bytes_a": len(ia["imem"]), "imem_bytes_b": len(ib["imem"]),
            "imem_sha256_a": ia["imem_sha256"], "imem_sha256_b": ib["imem_sha256"],
            "imem_differing_bytes": len(imem_diffs),
            "imem_identical": len(imem_diffs) == 0 and len(ia["imem"]) == len(ib["imem"]),
            "dmem_bytes_a": len(ia["dmem"]), "dmem_bytes_b": len(ib["dmem"]),
            "dmem_differing_bytes": len(dmem_diffs),
            "dmem_differing_offsets": [hex(x) for x in dmem_diffs[:64]],
            "image_sha256_a": ia["image_sha256"], "image_sha256_b": ib["image_sha256"],
            "image_identical": ia["image_sha256"] == ib["image_sha256"],
        })
        out.append(row)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("rom_a")
    ap.add_argument("rom_b")
    ap.add_argument("--json", type=Path)
    args = ap.parse_args(argv)

    a, b = load(args.rom_a), load(args.rom_b)
    rows = compare(a, b)
    result = {
        "files": {"a": {k: v for k, v in a.items() if k != "images"},
                  "b": {k: v for k, v in b.items() if k != "images"}},
        "ucodes": rows,
    }
    print("A: %s  sha256 %s" % (args.rom_a, a["file_sha256"][:16]))
    print("B: %s  sha256 %s" % (args.rom_b, b["file_sha256"][:16]))
    print()
    print("%-16s %-8s %-10s %-12s %-12s %s" % ("app", "desc", "imem", "imem diff", "dmem diff", "image"))
    for r in rows:
        if r.get("status"):
            print("%-16s %s" % (r["app_name"], r["status"]))
            continue
        print("%-16s %-8s %5d/%-5d %-12d %-12d %s" % (
            r["app_name"], "same" if r["descriptor_identical"] else "DIFF",
            r["imem_bytes_a"], r["imem_bytes_b"], r["imem_differing_bytes"],
            r["dmem_differing_bytes"],
            "identical" if r["image_identical"] else "different"))
        if 0 < r["dmem_differing_bytes"] <= 40:
            print("    dmem diffs at %s" % ", ".join(r["dmem_differing_offsets"]))
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(result, indent=2) + "\n")
        print("\nwrote", args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
