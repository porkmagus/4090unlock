# Ghidra + Kuna on the 4090 VBIOS option ROM

**Scope:** static, on macOS. Targets are `roms/A_legacy_x86.bin` (the 64 KiB x86
option-ROM image at file offset `0x9400` in both dumps) and, for context, the
extracted FWSEC image. No GPU was touched.

Question: does the VBIOS *code itself* read or write the Ada FEAT / speed-select
or fuse-select registers that the volatile unlock pokes?

---

## 1. Route: how each engine was driven

| Engine | Route | Note |
|---|---|---|
| Kuna 1.997 | `kuna functions/decompile-all --raw-image --target "x86:LE:16:Real Mode:default" --base 0xc0000` | Headerless raw image is a first-class Kuna input |
| Ghidra 12.2 | `analyzeHeadless` + `BinaryLoader`, `-processor x86:LE:16:Real Mode`, base `0xc0000` | REA's MCP raw-`x86` route pins `x86:LE:32:default` and **rejects** `REA_GHIDRA_LANGUAGE_ID` for raw imports ("Processor or compiler specification overrides cannot replace the admitted raw-binary import"), so the correct 16-bit import needs headless |

Ghidra scripts written for this: `tools/ghidra_scripts/DumpC.java` (decompile
every auto-discovered function) and `SeedDumpC.java` (create/disassemble a
caller-supplied address list, then decompile — used to seed Ghidra with Kuna's
inventory so both engines cover the same functions).

## 2. Coverage

| | Kuna | Ghidra |
|---|---|---|
| Function discovery (auto) | **338** (0.19 s) | 84 (auto-analysis) |
| After seeding Ghidra with Kuna's 338 | — | **336 decompiled**, 261 functions created, 2 failed |
| Full decompile time | 31 s for 338 bodies | headless pass, ~1–2 min |

## 3. Cross-engine agreement

Compared per address over the 336 common functions:

| Check | Result |
|---|---|
| I/O-port set per function | **336/336 identical** |
| Functions containing any `in`/`out` | 13 in both; **same set** |
| Port literals observed | identical lists (below) |
| `PCI config` helpers | same logic in both (see below) |

Both engines produce the same PCI config-space primitives:

```c
// c000:3947 (read)              // c000:396b (write)
if ((char)(bx >> 8) != 0xff) {   if ((char)(bx >> 8) != 0xff) {
  out(0xcf8, 0x80000000|...);      out(0xcf8, 0x80000000|...);
  in(0xcfc);                       out(0xcfc, value);
}                                }
```

Textual bodies differ in naming/formatting (expected — different printers), but
the hardware-visible facts agree exactly.

## 4. Hardware-access inventory of the ROM code

| Class | Ports / addresses | Meaning |
|---|---|---|
| PCI config space | `0xcf8` / `0xcfc` | standard CAM mechanism, read + write helpers |
| VGA sequencer / DAC / CRTC | `0x3c4`, `0x3ce`, `0x3c0`, `0x3c2`, `0x3c3`, `0x3cc`, `0x3da`, `0x3ba` | display init |
| Misc | `0x61`, `0x42`, `0x43`, `0x80` | PPI/timer/diagnostic |
| **FEAT / fuse-select block** | **none** | see below |

No occurrence of `0x00823804`, `0x00823818`, `0x0082381c`, `0x00823820`,
`0x0082059c`, `0x008207d4`, `0x008207d8`, `0x008200fc` or `0x0082038c` in either
engine's output.

**False lead, corrected.** A byte scan found an aligned dword `0x00820c14` at
image offset `0x7ec4`, inside `sub_c7eb2`. It is not a register reference: the
function is 16-bit real-mode code that uses 32-bit operand prefixes, and a
32-bit decode starting at the wrong boundary fabricates that immediate. The
correct 16-bit decode is:

```asm
c7ecd: 66 be 0c 02 90 00   mov esi, 0x90020c
c7ed3: 66 d1 da            rcr edx, 1
c7ed6: 72 06               jb  c7ede
c7ed8: e8 13 bb            call c39ee
c7edb: 66 03 d8            add ebx, eax
c7ede: 66 81 c6 00 40 00 00 add esi, 0x4000
c7ee5: e2 ec               loop c7ed3
```

i.e. a memory scan from `0x90020c` in `0x4000` steps — not a write to
`0x820c14`. Lesson: on this ROM, always confirm the instruction boundary before
treating a dword as an immediate.

## 5. What the ROM code actually does

- Display bring-up (VGA sequencer/DAC/CRTC ports), POST display switching.
- PCI config-space reads/writes via `0xCF8`/`0xCFC` (enumeration/BAR setup, not
  GPU register blocks).
- A linear memory scan at `0x90020c` (post-code region).
- No BAR0 MMIO access to the FEAT/fuse aperture, no `0x8238xx` reference.

This matches the earlier structural finding: on Ada the option ROM carries no
devinit script table (`i` is the *info* table), the EFI image is compressed, and
the Falcon firmware (including the FWSEC the unlock abuses) is encrypted.

## 6. Caveats

- Mixed code: the image is real-mode 16-bit, but parts use 32-bit operand
  prefixes; a single fixed Ghidra language cannot represent both optimally.
  The Kuna 16-bit target plus boundary-checked disassembly is the safer read.
- 2 of 338 seeded functions failed to decompile in Ghidra; both engines'
  inventories otherwise matched at 336.
- Kuna's raw-image mode cannot run `strings`/`xrefs` (object-metadata-only
  commands); call-graph xrefs were therefore derived from decompiled bodies.
- Static only: no execution, no hardware.

## 7. Reproduce

```bash
# Kuna
kuna functions roms/A_legacy_x86.bin --json --raw-image \
  --target "x86:LE:16:Real Mode:default" --base 0xc0000 --entry 0xc0003
kuna decompile-all roms/A_legacy_x86.bin --json --raw-image \
  --target "x86:LE:16:Real Mode:default" --base 0xc0000 --entry 0xc0003

# Ghidra (headless, correct 16-bit language)
analyzeHeadless /tmp/ghproj 4090rom -import roms/A_legacy_x86.bin \
  -processor "x86:LE:16:Real Mode" -loader BinaryLoader -loader-baseAddr 0xc0000 \
  -scriptPath tools/ghidra_scripts -postScript DumpC.java "$PWD/out.c"

# Ghidra seeded from Kuna's inventory (336/338)
analyzeHeadless /tmp/ghproj2 4090rom2 -import roms/A_legacy_x86.bin \
  -processor "x86:LE:16:Real Mode" -loader BinaryLoader -loader-baseAddr 0xc0000 \
  -scriptPath tools/ghidra_scripts -postScript SeedDumpC.java seeds.txt "$PWD/out.c"
```
