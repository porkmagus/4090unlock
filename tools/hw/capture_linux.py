#!/usr/bin/env python3
"""Read-only BAR0 speed-select capture from Linux (no kernel module, no writes).

This is the cold-state measurement tool for docs/07-windows-hardware-protocol.md.
It performs single 32-bit loads from a BAR0 mapping and nothing else: no config
writes, no firmware, no reset, no device enable.

Requirements and why:
  * root (CAP_SYS_RAWIO) - mapping PCI resources from sysfs needs it;
  * the GPU should have NO driver bound (blacklist nvidia/nouveau/nvidia_drm,
    do not bind vfio-pci) so the state is pre-driver. Check /sys/.../driver;
  * PCI memory decoding must already be enabled by the platform firmware. The
    tool reads the command register and refuses to enable it (that would be a
    config-space write);
  * the BAR0 resource must be non-zero and large enough for the offsets.

Live USB recipe (documented, not executed here):
    modprobe.blacklist=nvidia,nvidia_drm,nouveau vfio-pci.disable_vga=1
    mount /dev/sdX1 /mnt && cd /mnt && ./capture_linux.py --bdf 0000:01:00.0 \
        --stage power_on_post_vbios --json /mnt/cap-A-perf.json --prom prom.bin

Test without hardware (uses a fake sysfs tree; path logic, mmap and JSON only):
    python3 tools/hw/capture_linux.py --sysfs-root /tmp/fake --bdf 0000:01:00.0 --dry-run

Usage:
    python3 tools/hw/capture_linux.py --bdf 0000:01:00.0 --stage pre_driver --json cap.json
    python3 tools/hw/capture_linux.py --list
"""
from __future__ import annotations

import argparse
import json
import mmap
import os
import platform
import struct
import sys
import time

REGISTERS = [
    ("PMC_BOOT_0", 0x00000000),
    ("GFW_PLM", 0x00118128),
    ("GFW_BOOT", 0x00118234),
    ("GFW_CPUCTL", 0x00110100),
    ("WPR2_LO", 0x001FA824),
    ("WPR2_HI", 0x001FA828),
    ("WPR_CFG_PLM", 0x001FA7CC),
    ("WPR_PLM", 0x001FA7C4),
    ("FBPA_PLM", 0x009A0148),
    ("FEAT_OVR_ECC_PLM", 0x00823800),
    ("FEAT_OVR_PLM", 0x00823804),
    ("FEAT_OVR_QUADRO", 0x00823808),
    ("FEAT_OVR_ECC", 0x0082380C),
    ("FEAT_OVR_ECC_1", 0x00823810),
    ("FEAT_READOUT_0", 0x00823814),
    ("FEAT_READOUT_1", 0x00823818),
    ("FEAT_OVR_SM_SPD", 0x0082381C),
    ("FEAT_OVR_SM_SPD_1", 0x00823820),
    ("FEAT_OVR_ROW_REMAPPER", 0x00823824),
    ("FEAT_READOUT_2", 0x00823828),
    ("FUSE_SS_PLM", 0x008200FC),
    ("FUSE_SS_DP", 0x00820224),
    ("SECURE_FEAT_OVR_QUADRO_WR_SECURE", 0x0082038C),
    ("FUSE_SS_FFMA", 0x0082059C),
    ("FUSE_SS_FMLA16", 0x008207D4),
    ("FUSE_SS_FMLA32", 0x008207D8),
    ("FUSE_SS_IMLA0", 0x008207DC),
    ("FUSE_SS_IMLA1", 0x008207E0),
    ("FUSE_SS_IMLA2", 0x008207E4),
    ("FUSE_SS_IMLA3", 0x008207E8),
    ("FUSE_SS_IMLA4", 0x008207EC),
    ("FECS_FEAT_OVERRIDE_SM_SPEED_SEL", 0x00409664),
    ("FECS_FEAT_READOUT_1", 0x00409668),
    ("SM_ISSUE_RATE_MODIFIER", 0x00504204),
]
PROM_OFFSET = 0x300000
PROM_MIN = 0x10000


def read_hex(path, default=None):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def read_u16_config(devdir, offset):
    """Read one 16-bit config word through sysfs (a read, not a write)."""
    path = os.path.join(devdir, "config")
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            data = f.read(2)
        return struct.unpack("<H", data)[0]
    except (OSError, struct.error):
        return None


def enumerate_nvidia(root):
    out = []
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return out
    for name in names:
        if not name.startswith("0000:"):
            continue
        devdir = os.path.join(root, name)
        vendor = read_hex(os.path.join(devdir, "vendor"))
        device = read_hex(os.path.join(devdir, "device"))
        if vendor and vendor.lower() == "0x10de":
            out.append({"bdf": name, "device": device,
                        "driver": os.path.basename(os.path.realpath(os.path.join(devdir, "driver")))
                        if os.path.exists(os.path.join(devdir, "driver")) else None})
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--bdf", help="PCI address, e.g. 0000:01:00.0")
    ap.add_argument("--list", action="store_true", help="list NVIDIA PCI functions and exit")
    ap.add_argument("--stage", default="power_on_post_vbios",
                    choices=["power_on_post_vbios", "pre_driver", "post_driver",
                             "post_unlock", "post_flr", "post_power_cycle"])
    ap.add_argument("--json", help="write the capture record here")
    ap.add_argument("--prom", help="also dump the PROM window (BAR0+0x300000) to this file")
    ap.add_argument("--sysfs-root", default="/sys/bus/pci/devices", help=argparse.SUPPRESS)
    ap.add_argument("--dry-run", action="store_true", help="print the plan, touch nothing")
    args = ap.parse_args(argv)

    if args.list:
        for d in enumerate_nvidia(args.sysfs_root):
            print("%s  device=%s  driver=%s" % (d["bdf"], d["device"], d["driver"] or "none"))
        return 0
    if not args.bdf:
        ap.error("--bdf or --list required")

    devdir = os.path.join(args.sysfs_root, args.bdf)
    if not os.path.isdir(devdir):
        print("ERROR: %s not found" % devdir, file=sys.stderr)
        return 2
    vendor = read_hex(os.path.join(devdir, "vendor"))
    device = read_hex(os.path.join(devdir, "device"))
    if (vendor or "").lower() != "0x10de":
        print("ERROR: not an NVIDIA device (vendor=%s)" % vendor, file=sys.stderr)
        return 2
    driver = os.path.basename(os.path.realpath(os.path.join(devdir, "driver"))) \
        if os.path.exists(os.path.join(devdir, "driver")) else None
    command = read_u16_config(devdir, 0x04)
    mem_enabled = bool(command is not None and command & 0x2)
    resource0 = os.path.join(devdir, "resource0")
    bar_size = 0
    try:
        with open(os.path.join(devdir, "resource")) as f:
            first = f.readline().split()
            start, end = int(first[0], 16), int(first[1], 16)
            bar_size = end - start + 1 if end >= start else 0
    except (OSError, IndexError, ValueError):
        start = end = 0

    plan = {
        "tool": "capture_linux.py",
        "stage": args.stage,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": platform.node(),
        "kernel": platform.release(),
        "bdf": args.bdf,
        "vendor": vendor,
        "device": device,
        "driver_bound": driver,
        "pci_command": None if command is None else "0x%04X" % command,
        "memory_decode_enabled": mem_enabled,
        "bar0_size": bar_size,
        "registers": {name: "0x%08X" % off for name, off in REGISTERS},
        "prom_dump": args.prom,
    }

    if args.dry_run:
        print(json.dumps(plan, indent=2))
        return 0

    if driver:
        print("ERROR: driver '%s' is bound to %s. The cold capture needs the device "
              "unbound (blacklist nvidia,nvidia_drm,nouveau at boot)." % (driver, args.bdf),
              file=sys.stderr)
        return 3
    if command is None:
        print("ERROR: cannot read PCI config (root/CAP_SYS_RAWIO required)", file=sys.stderr)
        return 3
    if not mem_enabled:
        print("ERROR: PCI memory decoding is disabled. This tool will not enable it "
              "(that is a config-space write). Let platform firmware enable it, or use "
              "the UEFI capture path.", file=sys.stderr)
        return 3
    if bar_size < max(off for _, off in REGISTERS) + 4:
        print("ERROR: BAR0 size %#x too small for the register list" % bar_size, file=sys.stderr)
        return 3

    with open(resource0, "rb", buffering=0) as f:
        with mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ) as mm:
            values = {}
            for name, off in REGISTERS:
                values[name] = struct.unpack_from("<I", mm, off)[0]
            plan["values"] = {k: "0x%08X" % v for k, v in values.items()}
            if args.prom:
                n = min(PROM_MIN, max(0, bar_size - PROM_OFFSET))
                if n > 0:
                    with open(args.prom, "wb") as out:
                        out.write(mm[PROM_OFFSET:PROM_OFFSET + n])
                    plan["prom_bytes_written"] = n

    print(json.dumps(plan, indent=2))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(json.dumps(plan, indent=2) + "\n")
        print("wrote", args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
