# RTX 4090 Tensor Unlock & VBIOS — Comprehensive Findings

**Status:** static analysis complete; hardware verification pending.
**Scope:** two on-card VBIOS dumps (MSI RTX 4090, subsystem `1462:5103`), the
public unlock implementations, and the tooling required to analyze both.
**Nothing here was flashed, written to a GPU, or booted.** All claims are tied to
file offsets, hashes, or tool output, and carry a confidence label:

| Label | Meaning |
|---|---|
| **VERIFIED** | reproduced here from the artifact or tool output |
| **OBSERVED** | read from a tool/report, not independently reproduced |
| **INFERRED** | follows from evidence but not directly observed |
| **UNKNOWN** | cannot be established from available data |

---

## 0. The answer in plain language

The tensor-rate limit is **not in the VBIOS**. The board ROM never programs the
FEAT / speed-select registers, contains no devinit script that could, and its
Falcon firmware is encrypted and identical across both BIOS profiles. The
speed-select defaults are **fuse words**; the write gate is a hardware permission
default (`FEAT_OVR_PLM = 0xffffff8f`, L3-only). The volatile unlock works by
running signed firmware that opens those permissions and then writing two
registers from the host.

What the VBIOS actually contributes to the unlock is the **signed, encrypted
FWSEC firmware** the chain executes — and its plaintext DMEM interface, which is
the only surface a host patch touches. There is therefore no VBIOS-side lever for
a permanent unlock. Persistence requires replaying the unlock before the driver
binds (the existing UEFI projects), or breaking SEC2 authentication.

---

## 1. Artifacts and identity

| | BIOS A — performance | BIOS B — silent |
|---|---|---|
| File | `pc_extracted_files/bios_A_factory.rom` | `pc_extracted_files/bios_B_factory.rom` |
| Size | 2,048,000 B | 2,048,000 B |
| SHA-256 | `a4aade5a271fa793372da5f1196864b8918805465ba6cba31b0d09dc47619eae` | `15771e9243ae9ae673f2d662f610176cfabae4ccf457c70578f16b0ac26ea68f` |
| VBIOS version | `95.02.3C.40.B9` | `95.02.3C.40.B8` |
| Board ID | `MSINV510MH.2W0` | `MSINV510MH.2X0` |
| Subsystem / device | `1462:5103` / `10DE:2684` | `1462:5103` / `10DE:2684` |
| Power (min/default/max) | 150 / 450 / 480 W | 150 / 450 / 480 W |
| Thermal rated/max | 84 / 88 °C | 84 / 88 °C |
| Connectors | DP ×3 + HDMI | DP ×3 + HDMI |
| VBIOS image SHA-256 | `5c77fa2d939901248291cad783a29196a2e2c1bfcd0fb1cda35bc75b646ffc77` | `557fceb7660e54def4063a85b07cc6d65f9e4ac7d66db4a0b1ec795b9e680e23` |

Both dumps share generation metadata: Build GUID A `3D165227…07F9`, B
`AF156DC3…9073`; Build Number `32193434`; UEFI `0x7000B`; InfoROM
`G002.0000.00.03`, backup present; UEFI signed by Microsoft UEFI CA 2011
(**OBSERVED**, from the supplied spec sheets).

---

## 2. VBIOS anatomy

### 2.1 Container

The dumps are **not** bare option ROMs. Each is:

```
[ NVGI header 0x9400 ][ VBIOS image 0xE0000 ][ second copy 0xE0000 ][ tail 0x2AC00 ]
```

- Option-ROM signature `55 AA` at file offset `0x9400`; first PCIR at `+0x170`.
- The two on-card copies are **not** byte-identical: they diverge from image
  offset `0xD6C00` to the end (33,056 bytes differ in A, 33,057 in B).
  **VERIFIED**
- Across profiles, the *backup* copies differ by only **102 bytes**
  (`A_copy2 a3ee843a…` vs `B_copy2 9682097b…`), while the *active* copies differ
  by **1,448 bytes**. So the performance/silent settings live in the active
  copy; the second copy is largely profile-independent. **VERIFIED**

### 2.2 Image chain

| Image | Offset | Type | Length | Notes |
|---|---:|---|---:|---|
| Legacy x86 | `0x0` | `0x00` | `0xFC00` | plaintext, entropy 3.98, 57 % zero bytes |
| EFI | `0xFC00` | `0x03` | `0x14E00` | **compressed**, entropy 7.996 |
| Extension | `0x24A00` | `0xE0` | `0x6000` | starts `VN`, header `NPDS` |

The third image is why the unlock module's relocation constant is
`adjust = 0x24A00 − 0xFC00 = 0x14E00`; the BIT `p` pointer stores `0x83ED8` in
unrelocated coordinates, and `0x83ED8 + adjust = 0x98CD8` is the real ucode
table. **VERIFIED**

### 2.3 Tables

BIT table ids: `2, B, C, D, I, M, N, P, S, T, U, V, x, d, p, u, i, E, s`.

- **No devinit script table exists.** On Ada, `i` is the *Info* table and `I` is
  a 36-byte NVINIT stub. GPU bring-up is not in the option ROM. **VERIFIED**
- `p` (v2) points at the FALCON UCODE table. **VERIFIED**

### 2.4 Falcon firmware

Ucode table at `0x98CD8` (version 1, header 6, stride 6, 16 entries):

| Type | Ver | Image offset | 1 KiB entropy | Interpretation |
|---|---:|---:|---:|---|
| `0x01` | 1 | `0x02AA54` | 6.27 | plaintext table |
| `0x07` | 6 | `0x055708` | 5.77 | plaintext table |
| `0x08` | 1 | `0x07234C` | 6.00 | plaintext table |
| `0x45` | 7 | `0x034BB0` | 7.76 | encrypted/opaque |
| **`0x85`** | 7 | **`0x04515C`** | 7.76 | **FWSEC descriptor** |
| `0x49` | 5 | `0x0654A4` | 7.77 | encrypted/opaque |
| `0x89` | 5 | `0x06BBF8` | 7.75 | encrypted/opaque |

FWSEC descriptor `0x4515C`: size 812, image at `0x45488`, 66,304 B
(IMEM 62,720 + DMEM 3,456), `ucode_id` 9, `engine_mask` `0x400` (GSP),
2 signatures, signature versions bitmask `0x3` (768 signature bytes),
`pkc_off` 2,852, `interface_off` 28.
Image SHA-256 `6bbcb2fdffdd90bf548611242c0890300c0c45f3e65db12dff9d0a30abafd06e`
— **identical in A and B**. **VERIFIED**

- **IMEM entropy is 7.996 in every block, 0 % zero bytes** — ciphertext-grade,
  not compressible code. `envydis -m falcon` yields ~40 % unknown instructions at
  every offset. This matches the unlock project's own statement: "ROM inspection
  did not yield a plaintext Falcon image." **VERIFIED**
- **DMEM is plaintext** (entropy 4.86) and its interface header at offset 28
  reads `01 04 08 02` — version 1, header 4, stride 8, 2 entries — exactly what
  `gpu_unlock_fwsec_patch_frts()` requires (`==1`, `==4`, `==8`). **VERIFIED**

---

## 3. The unlock mechanism (from the public corpus)

The runtime transaction, in order:

1. Claim a cold card, save PCI state, allocate DMA.
2. Run the board ROM's **signed FWSEC-FRTS** on the GSP Falcon (reservation).
3. Start the **signed Booter** on SEC2 with crafted V67 signature data; SEC2
   authenticates/decrypts it; the payload performs four permission stores:
   `WPR_CFG 0x1FA7CC` → `FBPA 0x9A0148` → `WPR 0x1FA7C4` → `FEAT 0x823804`,
   requests marker `0x67B00001`, halts.
4. Verify marker, HALT, permissions.
5. Host writes **SS0 `0x82381C ← 0x88888888`** and **SS1 `0x823820 ← 0x8`**.
6. FLR; state survives; let the stock driver bind; benchmark.

### 3.1 Registers

| Register | BAR0 | Reported cold value | Role |
|---|---:|---|---|
| `FEAT_OVR_PLM` | `0x00823804` | `0xffffff8f` | write gate; L3-only by default |
| `FEAT_OVR_SM_SPD` (SS0) | `0x0082381C` | `0x44023025` | 8 × 4-bit fields |
| `FEAT_OVR_SM_SPD_1` (SS1) | `0x00823820` | `0x7` | 1 × 4-bit field (IMLA4) |
| `FEAT_READOUT_1` | `0x00823818` | `0x00410080` | effective rate, 9 × 3-bit fields |
| `FUSE_SS_FFMA` | `0x0082059C` | `0` | fuse default |
| `FUSE_SS_FMLA16` | `0x008207D4` | `0` | fuse default |
| `FUSE_SS_FMLA32` | `0x008207D8` | `1` | fuse default (1/2 rate) |
| `FUSE_SS_IMLA0..4` | `0x008207DC..EC` | `0/0/1/0/1` | fuse defaults |

Cold values are **OBSERVED on another AD102 card** (the public register report),
not measured on this one. The PLM field model (inferred from observed behaviour):
bits `[3:0]` read-enable per privilege level, `[7:4]` write-enable, `[23:8]`
source enable. `0x8f` = all levels read, only L3 writes. Each SS nibble: bit 3 =
override enable, bits 2:0 = selector (0 full, 1 half, 2 quarter, 3 eighth).
**OBSERVED / INFERRED**

### 3.2 Why the host cannot just write the registers

`FEAT_OVR_PLM` blocks L0–L2 writes, and the protected write must come from L3
context — hence the signed Booter ROP. The unlock's own report notes that direct
host writes were ignored *even after FWSEC-FRTS alone*. **OBSERVED**

---

## 4. Does the VBIOS set the tensor rate?

| # | Finding | Confidence |
|---|---|---|
| F1 | No devinit/init-script table exists in the VBIOS; `i` is Info, `I` is a stub | VERIFIED |
| F2 | The plaintext x86 image contains no reference to `0x823804/18/1C/20` or the `FUSE_SS_*` words | VERIFIED |
| F3 | The EFI image is compressed (entropy 7.996) and is display code, not a rate source | VERIFIED (compressed) / INFERRED (role) |
| F4 | FWSEC IMEM is encrypted (entropy 7.996, 0 % zeros); no plaintext Falcon image in the ROM | VERIFIED |
| F5 | FWSEC is present, well-formed, and matches the module's DMEM interface contract `1/4/8` | VERIFIED |
| F6 | Silent vs performance differ by 1,448 bytes, **none inside the ucode region**; FWSEC identical | VERIFIED |
| F7 | Two independent decompilers agree: 336 functions, 100 % identical I/O-port sets, 13 I/O functions, zero FEAT references | VERIFIED |
| F8 | angr cannot model 16-bit x86; a p-code emulator executes it correctly | VERIFIED |

### The correlation, stated precisely

| Unlock artifact | Present in this VBIOS? | Evidence |
|---|---|---|
| `FEAT_OVR_PLM` write | **No** | no reference in x86 ROM; no devinit; firmware encrypted |
| `SS0`/`SS1` writes | **No** | same |
| `FUSE_SS_*` defaults | **No** | fuse aperture; OTP is one-time |
| FWSEC-FRTS | **Yes** | ucode type `0x85`, descriptor `0x4515C`, interface `1/4/8/2` |
| Booter / V67 payload | **No** | shipped in the pinned NVIDIA 610.43.03 driver package |
| Board identity | **Yes** | `10DE:2684`, `1462:5103`, 450 W profile |

**Conclusion:** the VBIOS is the *supplier of signed firmware*, not the *source of
defaults*. H1 (writable VBIOS table determines defaults) is refuted for this
mechanism; H3 (fuse/strap) fits the register model; H4 (pre-OS replay) is the only
practical persistent experience; H2 (signed firmware establishes defaults) remains
possible but is unprovable here because the firmware is encrypted.

### One false lead, recorded

A byte scan flagged an aligned `0x00820C14` at image `0x7EC4` as a possible fuse
write. It is not: the function is 16-bit code using 32-bit operand prefixes, and
a 32-bit decode at the wrong boundary fabricates that immediate. The correct
decode is `66 BE 0C 02 90 00` → `mov esi, 0x90020C`, a memory scan in `0x4000`
steps. **VERIFIED**

---

## 5. Silent vs performance: what actually changes

- Active-copy delta: **1,448 bytes** at `0x8D`, `0xCE`, `0x24E` (BIT `B` board
  table), `0x438`, `0x47C..0x48B` (info strings), `0xFBFF`, `0x8A87F..0x8A88A`,
  `0x96917..0x969BA`, `0xDBE29..0xDBE43`, and a 1.2 KB block at
  `0xDFA48..0xDFF00` (entropy 7.76 — compressed/opaque, likely tuning data).
- Container-header delta: 1,481 bytes between `0x4000..0x92FF` (structured,
  entropy 5.89 — InfoROM/settings area).
- **Zero differences inside the ucode region `0x34BB0..0x73000`.**
- The VBIOS profile switch therefore changes power/thermal/tuning data only;
  it cannot change the tensor-rate mechanism. **VERIFIED**

---

## 6. Tooling program

### 6.1 Decompilers on the 16-bit ROM

| Engine | Route | Coverage | Agreement |
|---|---|---|---|
| **Kuna 1.997** | `--raw-image --target "x86:LE:16:Real Mode:default" --base 0xC0000` | **338 functions** (0.19 s discovery; 31 s full decompile) | reference inventory |
| **Ghidra 12.2** | `LegacyOptionROMLoader` (ghidra-firmware-utils) | 82 functions auto | 100 % of port sets |
| Ghidra + Kuna seeding | `SeedDumpC.java` creates Kuna's 338 addresses | **336 / 338 decompiled** | 336/336 identical I/O-port sets; same 13 I/O functions |

Both engines list the same port universe: PCI config `0xCF8/0xCFC`; VGA
`0x3C0/0x3C2/0x3C3/0x3C4/0x3CC/0x3CE/0x3DA/0x3BA`; misc `0x61/0x42/0x43/0x80`.
No FEAT/FUSE reference in either. **VERIFIED**

### 6.2 angr: not usable for this target

- `archinfo.arch_from_id("x86:16")` returns **32-bit** `ArchX86`; there is no
  16-bit x86.
- `angr-ghidra-core` (ported for angr 10: `sqlalchemy`, `variable_kb` →
  `proj.kb.variables`) ran but decoded 16-bit as 32-bit: true `call 0xC06A9`
  came out as `sub_66CF06AB()`. 54/84 "successes" are misdecodes. Reverted.
- Miasm 0.1.5's disassembler raises `NotImplementedError: not fully functional`.

### 6.3 The workable execution path: Ghidra p-code

`EmulatorHelper` executes whatever SLEIGH decodes. `EmuTrace.java` on
`c000:05F8` executed four instructions exactly (`xor ch,ch; shl al,2; or ch,al;
xor bl,bl`) and stopped at the `call` with
`Unimplemented CALLOTHER pcodeop (segment)` — the x86 SLEIGH asking the host for
`seg<<4 + off`. A `BreakCallBack` for the `segment` userop completes the path.
**VERIFIED**

### 6.4 Ports performed (this research)

| Project | Changes | State |
|---|---|---|
| `ghidra-firmware-utils` | `checkCanceled()` → `checkCancelled()` | ✅ built, installed, loader verified |
| `ghidra_falcon` | Gradle 9 (`archivesBaseName`/`baseName`/`main`) + Ghidra 12 `ImporterSettings` loader API | ✅ built, installed, `falcon:LE:32:v4/v5` verified |
| `AngryGhidra` | Java builds unmodified; Python driver → `from angr import claripy`, `ANGRYGHIDRA_PYTHON` | ✅ installed, engine verified on 32-bit control |
| `angr-ghidra-core` | `sqlalchemy`, `variable_kb` removal | ⚠️ ran, misdecodes 16-bit, reverted |
| `GhidraEmu` | JDOM1→JDOM2 import | ◐ ByteViewer API port remains (8 sites) |

### 6.5 Ecosystem survey

- **IDA catalog**: `plugins.hex-rays.com` is a SPA over
  `hexrayssa.github.io/plugin-repository/plugins/combined.json` — 269 plugins;
  only 4 firmware/UEFI-relevant (`efiXplorer` ×2, `fwhunt-ida`, `Binwalk`), none
  for 16-bit, GPU firmware, or Falcon.
- **Awesome lists** (`awesome-uefi-security`, `awesome-firmware-security`,
  `morluto/awesome-reverse-engineering`) supplied the UEFI/firmware tool map:
  efiSeek, UEFITool, BIOSUtilities, fiano, Qiling (EFI mode), efi_fuzz, tsffs,
  unblob, OFRAK, ripcord, Triton, BINSEC, faucon, dynamite.

---

## 7. Open questions and next steps

| # | Item | Why it matters | Effort |
|---|---|---|---|
| 1 | Cold register reads on **both switch positions** (`0x82381C/20/18/804`) | If equal across A/B, H1 is closed on hardware | needs Windows + tooling |
| 2 | Decompress the EFI image (`0xFC00..0x24A00`) | Last unexamined code region; firmware-utils UEFI loader or UEFITool | small |
| 3 | Identify `0x45`/`0x49`/`0x89` ucode entries | Could be booter/GSP components; all encrypted | small |
| 4 | Identify `0xDFA48..0xDFF00` profile block | Confirm it is tuning, not anything rate-related | small |
| 5 | Finish the `segment` userop callback | Unlocks concrete execution of the whole init path | ~20 lines |
| 6 | Evaluate `PcodeSym` (p-code vs angr lifting) | Only symbolic route that could handle 16-bit | medium |
| 7 | Build `faucon` and validate Ghidra's Falcon SLEIGH | Independent check of the new processor module | medium |
| 8 | Hardware unlock reproduction | Out of scope on this Mac (no GPU, no Windows) | — |

### What would change the conclusion

- A VBIOS field that feeds `FUSE_SS_*` — none exists in the mutable regions.
- A plaintext FWSEC in some ROM — none in these; SEC2 decrypts at run time.
- A devinit table in a different MSI SKU — possible but would still be gated by
  `FEAT_OVR_PLM`.

---

## 8. Reproduction

```bash
# 1. container -> active image
python3 - <<'PY'
d=open('pc_extracted_files/bios_A_factory.rom','rb').read()
open('/tmp/A_copy1.rom','wb').write(d[0x9400:0x9400+0xE0000])
PY

# 2. tables and ucode
nvbios -p pcir,info,bit,scripts /tmp/A_copy1.rom      # envytools, case-sensitive volume

# 3. FWSEC extraction (port of the unlock module's own parser)
python3 tools/fwsec_extract.py /tmp/A_copy1.rom --out /tmp/fwsec

# 4. Kuna: 338 functions, 16-bit real mode
kuna decompile-all /tmp/A_copy1.rom --json --raw-image \
  --target "x86:LE:16:Real Mode:default" --base 0xc0000 --entry 0xc0003

# 5. Ghidra with the correct loader
analyzeHeadless /tmp/p 4090 -import /tmp/A_copy1.rom -loader LegacyOptionROMLoader \
  -scriptPath tools/ghidra_scripts -postScript DumpC.java /tmp/ghidra.c

# 6. p-code execution probe
analyzeHeadless /tmp/p2 emu -import /tmp/A_copy1.rom -loader LegacyOptionROMLoader \
  -scriptPath tools/ghidra_scripts -postScript EmuTrace.java 0xc05f8 2000 /tmp/trace.txt
```

---

## Appendix A — Register quick reference (BAR0)

```
0x001FA7CC  WPR_CFG_PLM        gate (booter opens)
0x001FA7C4  WPR_PLM            gate
0x009A0148  FBPA_PLM           gate (unchanged in report)
0x00823804  FEAT_OVR_PLM       cold 0xFFFFFF8F (L3 write only)
0x00823818  FEAT_READOUT_1     cold 0x00410080
0x0082381C  FEAT_OVR_SM_SPD    cold 0x44023025 -> unlock 0x88888888
0x00823820  FEAT_OVR_SM_SPD_1  cold 0x00000007 -> unlock 0x00000008
0x0082059C  FUSE_SS_FFMA
0x008207D4  FUSE_SS_FMLA16
0x008207D8  FUSE_SS_FMLA32
0x008207DC..EC  FUSE_SS_IMLA0..4
0x0082038C  SECURE_FEAT_OVR_QUADRO_WR_SECURE
```

## Appendix B — File inventory

| Path | What |
|---|---|
| `RTX4090_Tensor_Unlock_Research.md` | original brief (407 lines) |
| `docs/01-vbios-unlock-cross-reference.md` | VBIOS ↔ unlock cross-reference, evidence chain |
| `docs/02-ghidra-kuna-vbios.md` | Ghidra vs Kuna on the 16-bit ROM |
| `docs/03-angr-and-plugins.md` | angr evaluation and the three plugin ports |
| `docs/04-plugin-landscape.md` | blocker → tool map, IDA catalog mining |
| `docs/FINDINGS.md` | this document |
| `~/porkmagusrepos/4090unlock-research/tools/fwsec_extract.py` | FWSEC extractor (port of the module parser) |
| `.../tools/vbios_xref.py` | ROM identity/PCIR/BIT/constant scanner |
| `.../tools/ghidra_scripts/{DumpC,SeedDumpC,EmuTrace}.java` | headless decompile, seeded decompile, p-code trace |
| `.../roms/` | extracted images, FWSEC blobs, decompiler outputs, traces |

## Appendix C — Tooling incident (unrelated to the GPU work)

Hermes' `execute_code` bridge called `handle_function_call(tool, args,
task_id=...)` without `session_id`, so `conduit_push`'s pre-tool policy failed
closed on every bridged call. The web provider (`web.backend: tinyfish`) was
healthy throughout; direct `web_search` worked. Session id now threads
handler → `execute_code` → kernel spawn (`HERMES_SESSION_ID`) → RPC dispatch and
was verified with a fresh kernel. **The running agent must be restarted for the
patch to take effect in a live session.**
