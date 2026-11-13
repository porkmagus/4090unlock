#!/usr/bin/env python3
"""Extract, decompress and inventory the EFI (GOP) image inside an NVIDIA VBIOS.

Read-only. This is the tool that closes the last unexamined plaintext-adjacent
region of the RTX 4090 ROM: the code-type-0x03 image was reported as
"compressed, entropy 7.996, not analysable". It is a UEFI PCI expansion-ROM
image (UEFI spec 13.4.2) whose payload is *EFI standard compression*
(EFI_DECOMPRESS_PROTOCOL version 1, a.k.a. Tiano) and it decompresses to a
PE32+ x86-64 boot-service driver.

Layout used (verified on the two dumps in pc_extracted_files/):

    +0x00  0xAA55
    +0x02  InitializationSize (512-byte units)
    +0x04  0x0EF1 EfiSignature
    +0x08  EfiSubsystem (11 = EFI boot service driver)
    +0x0A  EfiMachineType (0x8664 = x86-64)
    +0x0C  CompressionType (1 = EFI standard compression)
    +0x16  EfiImageHeaderOffset  ->  {u32 compressed_size, u32 uncompressed_size}
                                      followed by the compressed stream
    +0x18  PCIR offset

Decompression needs an EFI/Tiano decompressor. The Ghidra firmware-utils
extension ships one as a standalone C utility; build it once:

    curl -O https://raw.githubusercontent.com/al3xtjames/ghidra-firmware-utils/master/src/efidecompress/c/efidecompress.c
    cc -O2 -DCONFIG_UTIL -o efi_decompress efidecompress.c

and pass --decompressor. Without it the tool still extracts the compressed
payload and records its hashes and header fields.

Usage:
    python3 tools/efi_extract.py DUMP --decompressor ./efi_decompress --outdir out/
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vbios_chain import locate_rom_start, walk  # noqa: E402

# Registers the volatile unlock touches, plus the fuse words and the two
# other gate/fuse addresses that appear in the public register report.
FEATURE_REGISTERS = {
    0x00823800: "FEAT_OVR_ECC_PLM",
    0x00823804: "FEAT_OVR_PLM",
    0x00823808: "FEAT_OVR_QUADRO",
    0x0082380C: "FEAT_OVR_ECC",
    0x00823810: "FEAT_OVR_ECC_1",
    0x00823814: "FEAT_READOUT_0",
    0x00823818: "FEAT_READOUT_1",
    0x0082381C: "FEAT_OVR_SM_SPD (SS0)",
    0x00823820: "FEAT_OVR_SM_SPD_1 (SS1)",
    0x00823824: "FEAT_OVR_ROW_REMAPPER",
    0x00823828: "FEAT_READOUT_2",
    0x0082382C: "FEAT_OVR_ECC_2",
    0x008200FC: "FUSE_SS_PLM",
    0x00820224: "FUSE_SS_DP",
    0x0082038C: "SECURE_FEAT_OVR_QUADRO_WR_SECURE",
    0x0082059C: "FUSE_SS_FFMA",
    0x008207D4: "FUSE_SS_FMLA16",
    0x008207D8: "FUSE_SS_FMLA32",
    0x008207DC: "FUSE_SS_IMLA0",
    0x008207E0: "FUSE_SS_IMLA1",
    0x008207E4: "FUSE_SS_IMLA2",
    0x008207E8: "FUSE_SS_IMLA3",
    0x008207EC: "FUSE_SS_IMLA4",
    0x001FA7C4: "WPR_PLM",
    0x001FA7CC: "WPR_CFG_PLM",
    0x009A0148: "FBPA_PLM",
    0x00409664: "FECS_FEAT_OVERRIDE_SM_SPEED_SEL",
    0x00409668: "FECS_FEAT_READOUT_1",
    0x00504204: "SM_ISSUE_RATE_MODIFIER",
    0x00824148: "GU_FUSE_SEC2_UCODE1",
    0x008241E0: "FWSEC fuse (ucode id 9)",
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def parse_efi_header(image):
    if len(image) < 0x1A or image[:2] != b"\x55\xaa":
        raise ValueError("not an option-ROM image")
    hdr = {
        "signature": "0x%04X" % struct.unpack_from("<H", image, 0)[0],
        "initialization_size_blocks": struct.unpack_from("<H", image, 2)[0],
        "efi_signature": struct.unpack_from("<I", image, 4)[0],
        "efi_subsystem": struct.unpack_from("<H", image, 8)[0],
        "efi_machine_type": struct.unpack_from("<H", image, 0x0A)[0],
        "compression_type": struct.unpack_from("<H", image, 0x0C)[0],
        "efi_image_header_offset": struct.unpack_from("<H", image, 0x16)[0],
    }
    hdr["initialization_size_bytes"] = hdr["initialization_size_blocks"] * 512
    return hdr


def parse_pe(buf):
    if buf[:2] != b"MZ":
        raise ValueError("decompressed payload is not a PE image (no MZ)")
    pe = struct.unpack_from("<I", buf, 0x3C)[0]
    if buf[pe:pe + 4] != b"PE\x00\x00":
        raise ValueError("no PE signature")
    machine, nsec, timestamp, _sym, _nsym, optsz, chars = struct.unpack_from("<HHIIIHH", buf, pe + 4)
    opt = pe + 24
    magic = struct.unpack_from("<H", buf, opt)[0]
    info = {
        "machine": "0x%04X" % machine,
        "machine_name": {0x8664: "x86-64", 0x014C: "i386", 0xAA64: "AArch64"}.get(machine, "unknown"),
        "sections": nsec,
        "timestamp": timestamp,
        "characteristics": "0x%04X" % chars,
        "optional_magic": "0x%04X" % magic,
        "pe32_plus": magic == 0x20B,
        "entry_rva": struct.unpack_from("<I", buf, opt + 16)[0],
        "image_base": struct.unpack_from("<Q" if magic == 0x20B else "<I", buf, opt + 24)[0],
        "subsystem": struct.unpack_from("<H", buf, opt + 68)[0],
        "dll_characteristics": "0x%04X" % struct.unpack_from("<H", buf, opt + 70)[0],
    }
    table = opt + optsz
    secs = []
    for i in range(nsec):
        o = table + i * 40
        name = buf[o:o + 8].rstrip(b"\x00").decode("latin-1")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", buf, o + 8)
        schars = struct.unpack_from("<I", buf, o + 36)[0]
        secs.append({
            "name": name,
            "virtual_address": vaddr,
            "virtual_size": vsize,
            "raw_offset": rawptr,
            "raw_size": rawsize,
            "characteristics": "0x%08X" % schars,
            "executable": bool(schars & 0x20000000),
            "sha256": sha256(buf[rawptr:rawptr + rawsize]),
        })
    info["section_table"] = secs
    return info


def scan_constants(buf, sections, extra_range=None):
    """Find 32-bit immediate *byte patterns* naming a register of interest.

    Only executable sections are scanned. Both byte orders are tried, and for
    each hit the enclosing section and section-relative offset are reported so
    a hit can be checked at the instruction boundary before it is believed
    (this ROM class is known to fabricate immediates when decoded at the wrong
    boundary). Prefer scan_instructions() when capstone is available.
    """
    hits = []
    for sec in sections:
        if not sec["executable"]:
            continue
        body = buf[sec["raw_offset"]:sec["raw_offset"] + sec["raw_size"]]
        for value, name in sorted(FEATURE_REGISTERS.items()):
            for endian in ("little", "big"):
                pat = struct.pack("<I" if endian == "little" else ">I", value)
                idx = body.find(pat)
                while idx >= 0:
                    hits.append({
                        "register": name,
                        "offset": "0x%08X" % value,
                        "section": sec["name"],
                        "file_offset": sec["raw_offset"] + idx,
                        "rva": sec["virtual_address"] + idx,
                        "endian": endian,
                        "kind": "byte-pattern",
                    })
                    idx = body.find(pat, idx + 1)
        if extra_range:
            lo, hi = extra_range
            for rva in range(0, max(0, len(body) - 4)):
                v = struct.unpack_from("<I", body, rva)[0]
                if lo <= v <= hi:
                    hits.append({
                        "register": "range-scan",
                        "offset": "0x%08X" % v,
                        "section": sec["name"],
                        "file_offset": sec["raw_offset"] + rva,
                        "rva": sec["virtual_address"] + rva,
                        "endian": "little",
                        "kind": "byte-pattern",
                    })
    return hits


def scan_instructions(buf, sections, lo, hi):
    """Instruction-aware scan (x86-64) for real immediates and displacements.

    Reports only values that capstone decodes as an operand, which removes the
    false positives a raw byte scan produces. Returns None when capstone is not
    importable.
    """
    try:
        import capstone
    except ImportError:
        return None
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    x86 = capstone.x86
    hits = []
    for sec in sections:
        if not sec["executable"]:
            continue
        code = buf[sec["raw_offset"]:sec["raw_offset"] + sec["raw_size"]]
        for insn in md.disasm(code, sec["virtual_address"]):
            for op in insn.operands:
                if op.type == x86.X86_OP_IMM and lo <= (op.imm & 0xFFFFFFFF) <= hi:
                    hits.append({
                        "register": FEATURE_REGISTERS.get(op.imm, "unlisted-value"),
                        "offset": "0x%08X" % op.imm,
                        "section": sec["name"],
                        "rva": insn.address,
                        "instruction": "%s %s" % (insn.mnemonic, insn.op_str),
                        "kind": "immediate",
                    })
                elif op.type == x86.X86_OP_MEM and lo <= (op.mem.disp & 0xFFFFFFFF) <= hi:
                    hits.append({
                        "register": FEATURE_REGISTERS.get(op.mem.disp, "unlisted-value"),
                        "offset": "0x%08X" % (op.mem.disp & 0xFFFFFFFF),
                        "section": sec["name"],
                        "rva": insn.address,
                        "instruction": "%s %s" % (insn.mnemonic, insn.op_str),
                        "kind": "displacement",
                    })
    return hits


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("dump", type=Path)
    ap.add_argument("--decompressor", type=Path, help="efidecompress utility built with -DCONFIG_UTIL")
    ap.add_argument("--outdir", type=Path, default=Path("."))
    ap.add_argument("--json", type=Path)
    ap.add_argument("--scan-range", help="extra generic immediate scan, hex LOW:HIGH, e.g. 800000:840000")
    args = ap.parse_args(argv)

    raw = args.dump.read_bytes()
    rom = raw[locate_rom_start(raw):]
    images, error, adjust = walk(rom)
    efi_images = [im for im in images if im["code_type"] == 0x03]
    if not efi_images:
        raise SystemExit("no code-type-0x03 (EFI) image in the chain")
    args.outdir.mkdir(parents=True, exist_ok=True)

    result = {"file": str(args.dump), "file_sha256": sha256(raw), "bit_relocation_adjust": adjust,
              "chain_error": error, "efi_images": []}

    for im in efi_images:
        image = rom[im["start"]:im["end"]]
        hdr = parse_efi_header(image)
        at = hdr["efi_image_header_offset"]
        compressed, uncompressed = struct.unpack_from("<II", image, at)
        stream = image[at:at + 8 + compressed]
        entry = {
            "image_start": im["start"],
            "image_length": im["length"],
            "image_sha256": im["sha256"],
            "header": hdr,
            "declared_compressed_size": compressed,
            "declared_uncompressed_size": uncompressed,
            "stream_file_offset": im["start"] + at + 8,
            "stream_sha256": sha256(stream),
        }
        tag = "efi_%06x" % im["start"]
        stream_path = args.outdir / (tag + ".efi.bin")
        stream_path.write_bytes(stream)
        entry["stream_path"] = str(stream_path)
        print("%s: EFI image at %#x, %d bytes, compression type %d" % (
            args.dump.name, im["start"], im["length"], hdr["compression_type"]))
        print("  machine=0x%04X subsystem=%d  compressed=%d uncompressed=%d" % (
            hdr["efi_machine_type"], hdr["efi_subsystem"], compressed, uncompressed))

        if args.decompressor and hdr["compression_type"] == 1:
            with tempfile.TemporaryDirectory() as td:
                out = Path(td) / "out.bin"
                proc = subprocess.run([str(args.decompressor), str(stream_path), str(out)],
                                      capture_output=True, text=True)
                if proc.returncode != 0:
                    entry["decompress_error"] = (proc.stderr or proc.stdout).strip()
                    print("  decompression FAILED:", entry["decompress_error"])
                else:
                    buf = out.read_bytes()
                    pe_path = args.outdir / (tag + ".pe.bin")
                    pe_path.write_bytes(buf)
                    info = parse_pe(buf)
                    lo_hi = None
                    if args.scan_range:
                        lo, hi = (int(x, 16) for x in args.scan_range.split(":"))
                        lo_hi = (lo, hi)
                    named_hits = scan_constants(buf, info["section_table"])
                    instr_hits = scan_instructions(buf, info["section_table"], *lo_hi) if lo_hi else None
                    entry.update({
                        "decompressed_size": len(buf),
                        "decompressed_sha256": sha256(buf),
                        "decompressed_path": str(pe_path),
                        "pe": info,
                        "register_hits": named_hits,
                        "instruction_hits": instr_hits,
                    })
                    print("  decompressed %d bytes (sha256 %s), PE %s, %d sections, entry RVA %#x" % (
                        len(buf), sha256(buf)[:16], info["machine_name"],
                        info["sections"], info["entry_rva"]))
                    for sec in info["section_table"]:
                        print("    %-8s va=%#08x size=%#08x raw=%#08x %s" % (
                            sec["name"], sec["virtual_address"], sec["virtual_size"],
                            sec["raw_size"], "exec" if sec["executable"] else ""))
                    if named_hits:
                        print("  %d named-register byte-pattern hit(s)" % len(named_hits))
                        for h in named_hits[:20]:
                            print("    %-38s %s at %s+%#x" % (h["register"], h["offset"], h["section"], h["rva"]))
                    else:
                        print("  no named FEAT/FUSE register byte pattern in any executable section")
                    if instr_hits is None:
                        print("  instruction-aware scan skipped (capstone not importable)")
                    else:
                        assert lo_hi is not None
                        print("  instruction-aware scan %#x..%#x: %d operand hit(s)" % (
                            lo_hi[0], lo_hi[1], len(instr_hits)))
                        for h in instr_hits[:20]:
                            print("    %-20s %s at %s+%#x  %s" % (
                                h["register"], h["offset"], h["section"], h["rva"], h["instruction"]))
        result["efi_images"].append(entry)

    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n")
        print("wrote", args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
