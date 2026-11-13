#!/usr/bin/env python3
"""Decode a captured speed-select register set into a verdict.

Input: a JSON or key=value capture of the BAR0 words below, plus the stage at
which it was taken. Output: per-unit rate decode, the fuse-derived prediction,
a match/no-match verdict, and a machine-readable record for the evidence log.

Registers (BAR0):
    0x00823804 FEAT_OVR_PLM      write gate
    0x00823814 FEAT_READOUT_0
    0x00823818 FEAT_READOUT_1    effective per-unit rate, 9 x 3-bit, 0 = full
    0x0082381C SS0               override, 8 nibbles (bit3 = enable, bits2:0 = value)
    0x00823820 SS1               override, 1 nibble (IMLA4)
    0x0082059C FUSE_SS_FFMA
    0x008207D4 FUSE_SS_FMLA16
    0x008207D8 FUSE_SS_FMLA32
    0x008207DC..EC FUSE_SS_IMLA0..4

The fuse-then-readout correspondence (readout = 2 x fuse value, one field per
unit in fuse order) is an INFERENCE from one published cold capture; the tool
prints it as a prediction and never treats a match as proof of origin.

Usage:
    python3 tools/hw/decode_fingerprint.py capture.json --stage pre_driver
    python3 tools/hw/decode_fingerprint.py --self-test
"""
from __future__ import annotations

import argparse
import json
import sys

UNITS = ["FFMA", "FMLA16", "FMLA32", "IMLA0", "IMLA1", "IMLA2", "IMLA3", "IMLA4",
         "unit8(unnamed)"]
FUSE_REGS = {
    "FFMA": 0x0082059C,
    "FMLA16": 0x008207D4,
    "FMLA32": 0x008207D8,
    "IMLA0": 0x008207DC,
    "IMLA1": 0x008207E0,
    "IMLA2": 0x008207E4,
    "IMLA3": 0x008207E8,
    "IMLA4": 0x008207EC,
}
ALIASES = {
    "FEAT_OVR_SM_SPD": 0x0082381C,
    "FEAT_OVR_SM_SPD_1": 0x00823820,
    "FEAT_OVR_SM_SPEED_SELECT": 0x0082381C,
    "FEAT_OVR_SM_SPEED_SELECT_1": 0x00823820,
}
REG = {
    "FEAT_OVR_PLM": 0x00823804,
    "FEAT_READOUT_0": 0x00823814,
    "FEAT_READOUT_1": 0x00823818,
    "SS0": 0x0082381C,
    "SS1": 0x00823820,
}
STAGES = [
    "power_on_post_vbios",   # after GPU reset + option-ROM POST, before any driver
    "pre_driver",            # firmware up, no OS driver bound
    "post_driver",           # stock driver bound and running
    "post_unlock",           # after an authorised unlock transaction
    "post_flr",              # after a function-level reset
    "post_power_cycle",      # full AC removal and cold boot again
]
RATE = {0: "full", 1: "reserved/1", 2: "half", 3: "reserved/3", 4: "quarter",
        5: "reserved/5", 6: "eighth", 7: "reserved/7"}


def read_capture(path):
    text = open(path, "r", encoding="utf-8").read()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for sep in ("=", ":", " "):
                if sep in line:
                    k, v = line.split(sep, 1)
                    data[k.strip()] = v.strip()
                    break
    # capture_linux.py writes {"values": {"FEAT_READOUT_1": "0x...", ...}}
    if isinstance(data.get("values"), dict):
        data = dict(data, **data["values"])
    names = dict(REG)
    names.update(FUSE_REGS)
    names.update({"FUSE_SS_" + unit: off for unit, off in FUSE_REGS.items()})
    names.update(ALIASES)
    regs = {}
    for k, v in data.items():
        key = k.upper().replace("0X", "").strip()
        try:
            if key.startswith("0082"):
                regs[int(key, 16)] = int(str(v), 0)
            elif key in names:
                regs[names[key]] = int(str(v), 0)
        except (ValueError, TypeError):
            continue
    return data, regs


def decode(readout, ss0, ss1, fuses):
    fields = [(readout >> (3 * i)) & 7 for i in range(9)]
    nibbles = [(ss0 >> (4 * i)) & 0xF for i in range(8)]
    ss1_nib = ss1 & 0xF
    prediction = {}
    for unit, reg in FUSE_REGS.items():
        if reg in fuses:
            prediction[unit] = 2 * (fuses[reg] & 0x3)
    matches = None
    if prediction and readout is not None:
        matches = all(fields[UNITS.index(u)] == v for u, v in prediction.items())
    return fields, nibbles, ss1_nib, prediction, matches


def verdict(stage, fields, nibbles, ss1_nib, matches, plm):
    nonzero = [(UNITS[i], fields[i]) for i in range(9) if fields[i]]
    notes = []
    if plm is not None:
        notes.append("FEAT_OVR_PLM=0x%08X (%s)" % (
            plm, "L3-write-only default" if plm == 0xFFFFFF8F else "changed from default"))
    if not nonzero:
        state = "all nine units read full rate"
    else:
        state = "reduced: " + ", ".join("%s=%d(%s)" % (u, v, RATE.get(v, "?")) for u, v in nonzero)
    if stage in ("power_on_post_vbios", "pre_driver") and matches is True:
        origin = "consistent with fuse-derived defaults (readout matches 2 x FUSE_SS_* per unit)"
    elif stage in ("power_on_post_vbios", "pre_driver") and matches is False:
        origin = "does NOT match the fuse words: something else seeded the state before this read"
    elif stage in ("post_unlock", "post_flr"):
        origin = "post-transaction state; compare against the cold capture, not against fuses"
    else:
        origin = "stage does not isolate the default source"
    return {"stage": stage, "state": state, "origin": origin, "notes": notes,
            "ss0_nibbles": nibbles, "ss1_nibble": ss1_nib,
            "ss0_equals_unlock_value": nibbles == [8] * 8,
            "ss1_equals_unlock_value": ss1_nib == 8}


def self_test():
    # Published cold capture (docs/FINDINGS.md Appendix A) and the unlock values.
    cold = {REG["FEAT_OVR_PLM"]: 0xFFFFFF8F, REG["FEAT_READOUT_0"]: 0x00410000,
            REG["FEAT_READOUT_1"]: 0x00410080, REG["SS0"]: 0x44023025,
            REG["SS1"]: 0x00000007,
            0x0082059C: 0, 0x008207D4: 0, 0x008207D8: 1, 0x008207DC: 0,
            0x008207E0: 0, 0x008207E4: 1, 0x008207E8: 0, 0x008207EC: 1}
    fields, nibbles, ss1n, pred, matches = decode(
        cold[REG["FEAT_READOUT_1"]], cold[REG["SS0"]], cold[REG["SS1"]], cold)
    print("cold readout fields:", fields)
    print("fuse prediction:     ", pred, "match:", matches)
    v = verdict("pre_driver", fields, nibbles, ss1n, matches, cold[REG["FEAT_OVR_PLM"]])
    print(json.dumps(v, indent=2))
    assert fields == [0, 0, 2, 0, 0, 2, 0, 2, 0], fields
    assert matches is True

    unlocked = dict(cold)
    unlocked[REG["SS0"]] = 0x88888888
    unlocked[REG["SS1"]] = 0x00000008
    unlocked[REG["FEAT_READOUT_1"]] = 0
    unlocked[REG["FEAT_OVR_PLM"]] = 0xFFFFFFFF
    fields2, nibbles2, ss1n2, pred2, matches2 = decode(
        unlocked[REG["FEAT_READOUT_1"]], unlocked[REG["SS0"]], unlocked[REG["SS1"]], unlocked)
    v2 = verdict("post_unlock", fields2, nibbles2, ss1n2, matches2, unlocked[REG["FEAT_OVR_PLM"]])
    print(json.dumps(v2, indent=2))
    assert v2["ss0_equals_unlock_value"] and v2["ss1_equals_unlock_value"]
    assert fields2 == [0] * 9
    print("self-test OK")


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("capture", nargs="?", help="JSON or key=value register capture")
    ap.add_argument("--stage", choices=STAGES, default="pre_driver")
    ap.add_argument("--json", help="write the decoded record here")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        self_test()
        return 0
    if not args.capture:
        ap.error("capture file required unless --self-test")

    data, regs = read_capture(args.capture)
    missing = [n for n, a in list(REG.items()) + [(u, a) for u, a in FUSE_REGS.items()]
               if a not in regs]
    if REG["FEAT_READOUT_1"] not in regs:
        print("ERROR: FEAT_READOUT_1 (0x00823818) missing from the capture", file=sys.stderr)
        return 2
    fields, nibbles, ss1n, pred, matches = decode(
        regs.get(REG["FEAT_READOUT_1"]), regs.get(REG["SS0"], 0), regs.get(REG["SS1"], 0), regs)
    v = verdict(args.stage, fields, nibbles, ss1n, matches, regs.get(REG["FEAT_OVR_PLM"]))
    v["capture_file"] = args.capture
    v["missing_registers"] = missing
    v["raw"] = {("0x%08X" % k): ("0x%08X" % val) for k, val in sorted(regs.items())}
    print(json.dumps(v, indent=2))
    if args.json:
        open(args.json, "w", encoding="utf-8").write(json.dumps(v, indent=2) + "\n")
        print("wrote", args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
