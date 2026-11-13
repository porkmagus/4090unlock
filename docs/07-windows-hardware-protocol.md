# Factory register-state timeline: hardware protocol

**Status: procedure only. No hardware test in this document has been executed.**
The tools referenced here were tested offline (see §9); every hardware step is
marked **PENDING AUTHORIZATION**.

This document exists because the project has never measured the speed-select
state on the actual MSI RTX 4090, and because a read taken after Windows loads
is **not** a power-on fuse measurement. It defines what to capture, in what
order, with what tool, and what each capture can and cannot prove.

---

## 1. The constraint that shapes everything

**Windows user-mode cannot read BAR0.** There is no documented Windows API that
maps a display adapter's MMIO BAR from a user process. Reading `0x0082381C`
requires either a kernel-mode driver or firmware-level access. Administrator
rights do not change this. Practical consequences:

| Route | Viable? | Why |
|---|---|---|
| Windows PowerShell / CIM / nvidia-smi | **No** (for registers) | Exposes identity, driver, clocks, power — never MMIO |
| Windows + unsigned kernel driver | **No** | HVCI / Secure Boot block it; disabling them is a separate, riskier change |
| Windows + signed third-party peek driver | Discouraged | Closed provenance, and it would live on the machine we are trying to keep stable |
| **UEFI application before Windows** | **Yes** | The GOP driver itself reads `0x0082xxxx` during POST (`docs/05` §2.4), so the aperture is open pre-OS |
| **Linux live USB, no driver bound** | **Yes** | `resource0` can be `mmap`ed read-only with `CAP_SYS_RAWIO`; no module needed |
| Linux + read-only out-of-tree module after driver bind | Yes | `gpu_peek` style `ioread32` sampler; needs kernel headers |

So the "Windows measurement package" is honestly split: **Windows captures
identity and performance; the register read happens before Windows starts, on
the same cold boot.**

---

## 2. What is measured, and what each word means

| Register | BAR0 | Role | Why we want it |
|---|---:|---|---|
| `FEAT_OVR_PLM` | `0x00823804` | write gate | `0xFFFFFF8F` = L3-write-only default. Any other value means something already changed permissions |
| `FEAT_READOUT_1` | `0x00823818` | **effective rate**, 9 × 3-bit, 0 = full | The only word that says what the hardware is actually doing |
| `FEAT_OVR_SM_SPD` (SS0) | `0x0082381C` | override, 8 nibbles (bit3 = enable, bits2:0 = value) | `0x88888888` = all eight overridden to full |
| `FEAT_OVR_SM_SPD_1` (SS1) | `0x00823820` | override, 1 nibble (IMLA4) | `0x8` in every successful unlock |
| `FEAT_READOUT_0` | `0x00823814` | fuse feature readout | Cross-check |
| `FUSE_SS_FFMA` | `0x0082059C` | fuse default | Fuse-origin evidence |
| `FUSE_SS_FMLA16` | `0x008207D4` | fuse default | FP16-accumulate rate |
| `FUSE_SS_FMLA32` | `0x008207D8` | fuse default | **the decisive word for the cross-SKU test** |
| `FUSE_SS_IMLA0..4` | `0x008207DC..EC` | fuse defaults | INT/FP8 units |
| `FUSE_SS_PLM` | `0x008200FC` | fuse window permission | Is the fuse window readable at this stage |
| `SECURE_FEAT_OVR_QUADRO_WR_SECURE` | `0x0082038C` | secure-write permission | Secondary gate |
| `WPR_CFG_PLM` / `WPR_PLM` / `FBPA_PLM` | `0x001FA7CC` / `0x001FA7C4` / `0x009A0148` | the other three PLM gates | Full transaction evidence |
| `GFW_BOOT` / `GFW_CPUCTL` / `GFW_PLM` | `0x00118234` / `0x00110100` / `0x00118128` | GFW state | Tells you whether firmware has run yet |
| `PMC_BOOT_0` | `0x00000000` | chip identity | `0xbadf…` means the device is not accessible |
| `FECS_FEAT_OVR_SM_SPEED_SEL` / `FECS_FEAT_READOUT_1` | `0x00409664` / `0x00409668` | front-end copies | Independent confirmation of the SM view |
| `SM_ISSUE_RATE_MODIFIER` | `0x00504204` | issue-rate modifier | Explains "same readout, different throughput" cases |

Full list and reader: `tools/hw/capture_linux.py`.

### Decoding rule

* `FEAT_READOUT_1`: nine 3-bit fields, **0 = full**, 2 = half, 4 = quarter,
  6 = eighth (1/3/5/7 reserved). On the published cold AD102 capture the word is
  `0x00410080` → fields `0 0 2 0 0 2 0 2 0`.
* `SS0`/`SS1`: nibble `8` = enable + selector 0 (full); nibble `0` = no
  override; bit 3 without a sensible selector is a malformed write.
* The prediction "readout = 2 × matching `FUSE_SS_*` value" is an **inference**
  from the published capture. `tools/hw/decode_fingerprint.py` prints it as a
  prediction and reports match/no-match; a match is consistent with fuse origin,
  not proof of it.

---

## 3. Stage model

Each capture must carry its stage. A register value without a stage is not
evidence.

| Stage | When | What it establishes | What it does **not** |
|---|---|---|---|
| **S0 `power_on_post_vbios`** | Fully powered off, cold boot, option ROM POST done, **no OS driver bound** | The closest observable approximation to the factory default | It is *not* a raw fuse read: GPU boot firmware and the option ROM have already run |
| **S1 `pre_driver`** | Firmware up (GFW boot complete), still no driver | Whether firmware left the state alone | Same caveat as S0 |
| **S2 `post_driver`** | Stock NVIDIA driver bound, idle | Whether driver init changes anything | Never quote as a cold default |
| **S3 `post_unlock`** | Immediately after an authorised unlock | Gate 2 of the acceptance system | Says nothing about persistence |
| **S4 `post_flr`** | After a function-level reset | Whether state survives FLR | Not the same as a power cycle |
| **S5 `post_power_cycle`** | AC removed, discharged, cold boot again | True persistence | Only meaningful if S3 passed |

The rule the project has been missing: **S0 must be captured with the GPU
unbound, before any driver, and labelled as post-POST — never as "power-on fuse
values".**

---

## 4. Path A — Linux live USB, cold, no driver (preferred)

**Why preferred:** no kernel module to build, no signing, no writes, and the
mapping is a plain read-only `mmap` of `resource0`.

### A.1 Prepare the stick (on the Mac)

1. Download a current Linux ISO (any distro with Python 3 and `mmap`; a
   Debian/Ubuntu live image is fine). Verify its published SHA-256.
2. Write it to a USB stick with `dd` (macOS: `diskutil list`, then
   `sudo dd if=image.iso of=/dev/rdiskN bs=4m`). **Verify the device name three
   times; `dd` to the wrong disk destroys it.**
3. Copy `tools/hw/capture_linux.py` and `tools/hw/decode_fingerprint.py` to a
   second FAT32 stick (the evidence stick), not the live image.

### A.2 Boot with the GPU unbound

At the bootloader, add:

```
modprobe.blacklist=nvidia,nvidia_drm,nouveau,nova_core
```

Do **not** bind `vfio-pci`: a bound driver claims the device and can make
`resource0` inaccessible. Do not start X/Wayland.

### A.3 Capture

```bash
sudo -i
python3 capture_linux.py --list                       # find the BDF, confirm driver=none
python3 capture_linux.py --bdf 0000:01:00.0 \
    --stage power_on_post_vbios \
    --json /media/EVIDENCE/cap-S0-perf.json \
    --prom /media/EVIDENCE/prom-perf.bin
```

Cross-check with envytools' independent reader if available:

```bash
nvapeek 0x82381c 0x823820 0x823818 0x823804 0x8207d8
```

Two independent tools agreeing on the same words is worth more than one tool
with a nicer report.

### A.4 Failure modes and what they mean

| Symptom | Meaning | Action |
|---|---|---|
| `driver_bound` is not null | Something claimed the GPU | Fix the blacklist; do not capture |
| `memory_decode_enabled: false` | Platform firmware left MEM decoding off | Do **not** enable it by hand (config write). Capture from the UEFI path instead |
| `resource0` mmap `EACCES`/`EPERM` | Missing `CAP_SYS_RAWIO` or IOMMU policy | Run as root; check `dmesg` |
| All words `0x00000000` | BAR mapped but device not decoding, or wrong BAR | Check `lspci -v` BAR0 size; do not proceed |
| `0xBADF…` in high bits | Engine in reset / inaccessible | Reboot; capture again |

### A.5 Repeat for the other BIOS position

Power off, switch the card's physical BIOS selector **while unpowered**, boot
the same stick, capture to `cap-S0-silent.json`. Compare with
`decode_fingerprint.py`.

---

## 5. Path B — UEFI pre-OS read

Use when the Linux path is unavailable or when you want a capture *before* any
OS has run at all.

**Mechanism.** A UEFI application locates the GPU handle, opens
`EFI_PCI_IO_PROTOCOL`, and calls `Mem.Read` with `BarIndex = 0` and the offsets
in §2. That is exactly how the GOP driver reaches `0x0082xxxx`, and how the
public UEFI unlockers read the same words. Reads only; no `Mem.Write`, no
config-space writes.

**What it must do (acceptance for the tool itself):**

1. Print the device id and subsystem id from PCI config, and abort on anything
   other than `10DE:2684`.
2. Read and print every word in §2, one line each, with the offset.
3. Read `FEAT_READOUT_1` twice, 100 ms apart, and print both — a changing value
   means something else is running.
4. Refuse to write anything; the source must contain no `Mem.Write`,
   `Pci.Write`, or config write path.
5. Dump the PROM window at `BAR0 + 0x300000` (at least 64 KiB) to a file for
   offline FWSEC verification, so the capture proves *which* VBIOS was active.

**Status: NOT BUILT in this stage.** No UEFI toolchain was exercised. The two
existing reviewed code bases in the research tree
(`nv-uefi-unlocker`, `gpu-unlock-4090-windows`) both contain the required
`EFI_PCI_IO` read path and are the right starting points; a read-only build
should be cut from one of them rather than written from scratch, and must pass
the five checks above before it is used on the card.

---

## 6. Path C — Windows (identity, ROM, benchmarks only)

Windows cannot supply the register capture, but it is where the *performance*
gate and the identity record live. Package:

```
EVIDENCE\
  identity\
    nvidia-smi.txt            identity, driver, VBIOS, power limit
    pnp.txt                   device instance path (subsystem id)
    board.txt                 motherboard + BIOS
    secureboot.txt            Confirm-SecureBootUEFI, BitLocker status
    gpuz-screenshot.png       optional, human-readable cross-check
  rom\
    bios_current.rom          nvflash --save (read-only)
    bios_current.sha256
  regs\
    cap-S0-perf.json          from Path A or B, same boot
  bench\
    stock-<date>.json         gate 3 baseline
    unlocked-<date>.json      gate 3 test
  log\
    transcript.txt            every command, with timestamps
```

`tools/hw/Collect-RTX4090-Baseline.ps1` produces the `identity\` folder and a
manifest. It does not touch BAR0, does not flash, does not change boot order.
**It has not been executed: no Windows host was available in this stage.**

Rules for the Windows side:

* Record the **driver version and CUDA version** with every benchmark; the
  unlock is driver-version sensitive (the pinned firmware is 610.43.03).
* Disable any undervolt/overclock for the baseline runs, then re-test with it as
  a separate condition.
* Capture `nvidia-smi --query-gpu=clocks.sm,power.draw,temperature.gpu` during
  the run, not before it.

---

## 7. Safety rules and approvals

| Action | Approval | Notes |
|---|---|---|
| Read registers via Path A/B | **Standing approval** (read-only) | Still: no writes, no module loading beyond the live environment |
| Windows identity/ROM backup | Standing approval | `nvflash --save` only |
| Unlock transaction (S3) | **Explicit, per-session** | Separate authorisation; never part of a measurement run |
| FLR (S4) | Explicit | Can leave the card unusable until reboot |
| BIOS switch position change | Explicit, and **only with AC removed** | Physical switch |
| VBIOS flash, fuse programming, Secure Boot change, motherboard firmware | **Not authorised in this project stage** | Out of scope |

Stop immediately on: any `0xBADF…` read, display loss, Xid in `dmesg`, power or
temperature excursion, or a readout that changes between two reads in the same
stage.

---

## 8. What the captures will decide

| Comparison | Decision it enables |
|---|---|
| S0 perf vs S0 silent | Does the VBIOS profile seed any part of the state? (Prediction: no difference. If different, the VBIOS *does* control something and `docs/09` changes.) |
| S0 vs S1 | Does GPU firmware modify the state after POST? |
| S1 vs S2 | Does the stock driver modify it? |
| S0 vs S3 | Did the unlock actually change the effective rate (gate 2) |
| S3 vs S4 vs S5 | Persistence across reset and power loss |
| 4090 S0 vs professional AD102 S0 | **Fuse vs firmware origin** (`docs/06` §7) |

---

## 9. Tooling status (what was actually tested)

| Tool | Test performed | Result |
|---|---|---|
| `tools/hw/capture_linux.py` | Full path against a synthetic sysfs tree (fake `resource0`, 16 MiB sparse file, config with MEM enabled) | PASS — enumerated device, read config, mmap'd, decoded all 33 words |
| `tools/hw/decode_fingerprint.py` | `--self-test` (published cold values + unlock values) and the synthetic capture from above | PASS — cold fields `0 0 2 0 0 2 0 2 0`, prediction match `True`; unlock state detected |
| `tools/hw/Collect-RTX4090-Baseline.ps1` | **Not executed** — no PowerShell/Windows host available | Unverified |
| UEFI read-only app | **Not built** — no UEFI toolchain in this stage | Unverified |
| Real GPU | **Not present on this host** | Nothing hardware-related was run |

Anything in this document that says "read", "capture" or "boot" describes a
procedure, not a result.
