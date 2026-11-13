# VBIOS ↔ Tensor Unlock cross-reference (A: performance, B: silent)

**Scope:** static analysis on macOS. No GPU was read, flashed, or booted for this
document. Every claim below is tied to a file offset, a hash, or a tool output.

**Question:** the volatile unlock works by opening four PLM permission registers
and then writing two speed-select registers. Does anything in the board VBIOS
supply, gate, or persist that state — and if not, what *is* the VBIOS's role in
the chain?

---

## 1. Artifacts

| | BIOS A — performance | BIOS B — silent |
|---|---|---|
| File | `pc_extracted_files/bios_A_factory.rom` | `pc_extracted_files/bios_B_factory.rom` |
| Size | 2,048,000 B | 2,048,000 B |
| SHA-256 (dump) | `a4aade5a271fa793372da5f1196864b8918805465ba6cba31b0d09dc47619eae` | `15771e9243ae9ae673f2d662f610176cfabae4ccf457c70578f16b0ac26ea68f` |
| VBIOS version | `95.02.3C.40.B9` | `95.02.3C.40.B8` |
| Board ID string | `MSINV510MH.2W0` | `MSINV510MH.2X0` |
| Subsystem | `1462:5103` | `1462:5103` |
| Device | `10de:2684` | `10de:2684` |
| Power default / max | 450 W / 480 W | 450 W / 480 W |
| VBIOS image (extracted) SHA-256 | `5c77fa2d939901244…` | `557fceb7660e54de17…` |

Both dumps are **containers**, not bare option ROMs: an `NVGI` header of
`0x9400` bytes followed by two full `0xE0000`-byte VBIOS images, then a
`0x2AC00`-byte tail. The option ROM begins at file offset `0x9400` (`55 AA`,
PCIR at `+0x170`).

The two on-card copies are **not** byte-identical: within each file they diverge
from image offset `0xD6C00` to the end (~37 KB). Cross-file, the *backup* copies
are nearly profile-independent (`A_copy2` vs `B_copy2` = **102** differing
bytes), while the *active* copies differ by **1,448** bytes. So the
performance/silent settings live in the active copy; the second copy is largely
a shared, stale image.

---

## 2. Registers the unlock writes (from the unlock corpus)

| Register | BAR0 offset | Cold value (reported on AD102) | Role |
|---|---|---|---|
| `WPR_CFG_PLM` | `0x001fa7cc` | — | permission gate (opened by signed booter) |
| `WPR_PLM` | `0x001fa7c4` | — | permission gate |
| `FBPA_PLM` | `0x009a0148` | — | permission gate (no observed change) |
| **`FEAT_OVR_PLM`** | `0x00823804` | `0xffffff8f` | gates writes to SS0/SS1: only L3 may write |
| **`FEAT_OVR_SM_SPD` (SS0)** | `0x0082381c` | `0x44023025` | 8 × 4-bit fields; bit 3 = enable, bits 2:0 = rate |
| **`FEAT_OVR_SM_SPD_1` (SS1)** | `0x00823820` | `0x7` | 1 × 4-bit field (IMLA4) |
| `FEAT_READOUT_1` | `0x00823818` | `0x00410080` | effective rate readout, 9 × 3-bit fields |
| Unlock values | — | — | SS0 ← `0x88888888`, SS1 ← `0x8` |

The **defaults themselves** are fuse words in the same `0x0082xxxx` aperture:
`FUSE_SS_FFMA` `0x0082059c`, `FUSE_SS_FMLA16` `0x008207d4`, `FUSE_SS_FMLA32`
`0x008207d8`, `FUSE_SS_IMLA0..4` `0x008207dc..0x008207ec`, plus
`SECURE_FEAT_OVR_QUADRO_WR_SECURE` `0x0082038c`.

---

## 3. Method

- `envytools` `nvbios` (built locally from source, ARM64) for the PCI/BIT/D CB
  table walk.
- `tools/fwsec_extract.py` — a byte-for-byte port of the unlock module's own
  parser (`gpu-unlock-ada/kernel/gpu_unlock/vbios_610.c`, GPL-2.0): same ROM
  chain walk, same BIT token filter (`0x70 0x02`), same ucode-table layout, same
  descriptor validation.
- Shannon entropy per region, to separate code from ciphertext.
- Raw constant scan for every register above, in little- and big-endian 32-bit
  and 16-bit forms, restricted to plaintext regions.

---

## 4. Findings

**F1 — There is no devinit script in this VBIOS.**
The BIT table list is `2, B, C, D, I, M, N, P, S, T, U, V, x, d, p, u, i, E, s`.
On Ada, `i` is the **Info** table (version strings, GUID), not init scripts;
`I` is a 36-byte NVINIT stub. There is no register-programming script table at
all — GPU bring-up lives in firmware, not in the option ROM.

**F2 — The x86 option ROM never references the FEAT or fuse-select registers.**
The legacy image (`0x000..0xFC00`, entropy 3.98, 57 % zeros — plaintext) contains
no 32-bit occurrence of `0x00823804`, `0x00823818`, `0x0082381c`, `0x00823820`,
`0x0082059c`, `0x008207d8`, `0x008200fc` or `0x0082038c`.

**F3 — The EFI image is compressed.** `0xFC00..0x24A00`, entropy 7.996. It is a
display/GOP blob; nothing in it is addressable as code without decompression,
and it is not the tensor-rate default source.

**F4 — The ROM's Falcon firmware is encrypted, not merely obfuscated.**
The ucode table at `0x98CD8` (16 entries, header 6, stride 6) points at:

| Type | Ver | Image offset | Entropy (1 KiB) | Interpretation |
|---|---|---|---|---|
| `0x01` | 1 | `0x02aa54` | 6.27 | plaintext table |
| `0x07` | 6 | `0x055708` | 5.77 | plaintext table |
| `0x08` | 1 | `0x07234c` | 6.00 | plaintext table |
| `0x45` | 7 | `0x034bb0` | 7.76 | encrypted firmware |
| **`0x85`** | 7 | **`0x04515c`** | 7.76 | **FWSEC descriptor (used by unlock)** |
| `0x49` | 5 | `0x0654a4` | 7.77 | encrypted firmware |
| `0x89` | 5 | `0x06bbf8` | 7.75 | encrypted firmware |

The FWSEC **IMEM is 7.996 entropy in every 7.8 KB block with 0 % zero bytes** —
ciphertext-grade. Its DMEM (3,456 B, entropy 4.86) is plaintext. `envydis
-m falcon` produces ~40 % `unknown instruction` at every offset, consistent with
encrypted input rather than an ISA mismatch. The unlock project reached the same
conclusion independently: "ROM inspection did not yield a plaintext Falcon
image."

**F5 — FWSEC is present, well-formed, and matches the unlock module's contract.**
The image is a three-image chain: x86 legacy at `0x0` (type `0x00`), a compressed
EFI image at `0xFC00` (type `0x03`), and a `VN`/`NPDS` extension at `0x24A00`
(type `0xE0`). The module's relocation constant for this ROM is therefore
`adjust = 0x24A00 - 0xFC00 = 0x14E00`; the BIT `p` pointer stores `0x83ED8` in
unrelocated coordinates and `0x83ED8 + adjust = 0x98CD8`, which is exactly where
a valid ucode table header (`01 06 06 10`) sits.
Descriptor at `0x04515c`: size 812, image at `0x045488`, 66,304 B
(62,720 IMEM + 3,456 DMEM), `ucode_id` 9, `engine_mask` `0x400` (GSP),
2 signatures, signature versions bitmask `0x3`, `pkc_off` 2,852,
`interface_off` 28. The DMEM interface header at offset 28 reads **`01 04 08 02`**
— version 1, header 4, stride 8, 2 entries — exactly the values
`gpu_unlock_fwsec_patch_frts()` requires (`==1`, `==4`, `==8`).
FWSEC image SHA-256: **`6bbcb2fdffdd90bf548611242c0890300c0c45f3e65db12dff9d0a30abafd06e`**,
**identical in A and B**.

**F6 — The silent/performance difference touches no firmware and no BIT table.**
A vs B (active copy): 1,448 differing bytes, confined to
`0x8d`, `0xce`, `0x24e` (BIT `B` board table), `0x438`, `0x47c..0x48b` (info
strings), `0xfbff`, `0x8a87f..0x8a88a`, `0x96917..0x969ba`, `0xdbe29..0xdbe43`,
and `0xdfa48..0xdfeff` (a 1.2 KB, 7.76-entropy settings block).
**Zero differences** fall inside the ucode region `0x34bb0..0x73000`. The profiles
differ in tuning/InfoROM data only; the tensor-rate mechanism is untouchable
from either profile.

---

## 5. The actual correlation

| Unlock artifact | Present in this VBIOS? | Evidence |
|---|---|---|
| `FEAT_OVR_PLM` write (`0x823804`) | **No** | no reference in x86 ROM, no devinit, firmware encrypted |
| `SS0` / `SS1` writes (`0x82381c`/`0x823820`) | **No** | same |
| `FUSE_SS_*` cold defaults | **No** | fuse aperture; VBIOS cannot program OTP |
| FWSEC-FRTS firmware | **Yes** | ucode type `0x85`, descriptor `0x4515c`, interface `1/4/8/2` |
| Signed Booter / `v67` payload | **No** | comes from the pinned 610.43.03 driver package, not the ROM |
| Board identity the module checks | **Yes** | `10de:2684`, subsystem `1462:5103`, 450 W profile |

So the correlation is real but **inverted from the persistence hypothesis**. The
VBIOS is not the place where the tensor rate is set; it is the **supplier of the
signed, encrypted FWSEC firmware that the unlock chain executes**, and its
plaintext DMEM interface is the only surface the host-side patch touches. The
speed-select defaults are fuse words; the PLM gate is a hardware permission
default (`0xffffff8f` = only L3 writes).

**Consequence for permanence:** a VBIOS-side permanent unlock would require
either (a) a mutable field that seeds `FUSE_SS_*` — none exists, and OTP is
one-time — or (b) patching FWSEC/Booter — which breaks SEC2 authentication and
is encrypted besides. What remains is replay before the driver binds (the
existing UEFI projects). That matches H3 (fuse/strap) and refutes H1 (writable
VBIOS table) for the tensor-rate path specifically.

---

## 6. Falsifiable next steps

1. **Cold-state comparison (hardware):** read `0x82381c`, `0x823820`, `0x823818`,
   `0x823804` on both switch positions before any unlock. If they are identical
   across A and B, the VBIOS provably does not seed them. *(Requires Windows +
   register access tooling; not doable on this Mac.)*
2. **Decompress the EFI image** and scan it; expected null result, but it closes
   the last plaintext-adjacent region.
3. **Diff the InfoROM block** `0xDFA48..0xDFF00` against a second MSI 4090 SKU to
   learn whether it is power/thermal policy (expected) or something else.
4. **Confirm the backup copy** (`0xD6C00..0xE0000`) is a stale image: compare it
   to a fresh NVFlash dump after a profile switch.

## 7. Reproduce

```bash
# container -> image
python3 - <<'PY'
d=open('pc_extracted_files/bios_A_factory.rom','rb').read()
open('/tmp/A_copy1.rom','wb').write(d[0x9400:0x9400+0xE0000])
PY
# tables (envytools, built from source on a case-sensitive volume)
nvbios -p pcir,info,bit,scripts /tmp/A_copy1.rom
# FWSEC
python3 tools/fwsec_extract.py /tmp/A_copy1.rom --out /tmp/fwsec
# entropy / constant scan are in the analysis transcript; thresholds above
```
