# Static closure: EFI image, Falcon ucode, profile delta, F1–F8

**Status:** static analysis complete for every region that can be read without
decrypting SEC2 or executing firmware. Hardware measurements remain pending.
**Scope:** the two dumps in `pc_extracted_files/`, read-only.
**Nothing here was flashed, written to a GPU, or booted.**

Every claim carries one of: **VERIFIED** (reproduced here from the artifact or
tool output), **OBSERVED** (read from a third-party report), **INFERRED**
(follows from evidence, not directly observed), **UNKNOWN**.

Machine-readable companion: `research/static_evidence.json` (regenerate with
`tools/static_evidence.py`). The JSON is the source of the numbers quoted here.

---

## 0. What changed in this pass

The previous findings closed the VBIOS question with three claims that were
honest but incomplete:

1. "The EFI image is compressed; nothing in it is addressable."
   → It **is** compressed, and it **does** decompress: it is a PE32+ x86-64 UEFI
   GOP driver, 164,144 bytes, 302 functions, and it contains no FEAT/fuse
   speed-select reference. The last unexamined code region is now examined.
2. "`0x45`/`0x49`/`0x89` are encrypted/opaque; function unknown."
   → They are **four more signed firmware descriptors** (`0x45` and `0x85` are
   the debug and production FWSEC; `0x49` and `0x89` are the debug and production
   variants of app id `0x09`), with engine masks, ucode ids, sizes, two RSA
   signatures each, and plaintext DMEM containing build stamps and crypto-engine
   strings. Their role is now bounded by metadata, not by entropy.
3. "Silent and performance differ by a 1.2 KB opaque block at
   `0xDFA48..0xDFF00`."
   → The delta is **1,448 bytes in 34 ranges**, and the `0xDFA48` area is part
   of an **InfoROM/provisioning record area**, not a tuning blob. The records
   carry per-record 32-byte integrity fields that change with the profile.

None of this moves the tensor-rate default out of the fuse/strap hypothesis. It
does narrow what the VBIOS can still be hiding.

---

## 1. Offset map (container → image)

Both dumps are 2,048,000 bytes:

| Container region | File offset | Length | Content |
|---|---:|---:|---|
| NVGI header | `0x000000` | `0x9400` | 0x0381/0x8024 signature words, settings, 0xFF pad |
| VBIOS copy 1 | `0x009400` | `0xE0000` | 917,504 B; the active image |
| VBIOS copy 2 | `0x0E9400` | `0xE0000` | 917,504 B; the backup image |
| Tail | `0x1C9400` | `0x2AC00` | 175,104 B |

Inside copy 1 the option-ROM chain is four images (**VERIFIED**,
`tools/vbios_chain.py`):

| # | Image offset | Length | Type | Data sig | Notes |
|---|---:|---:|---:|---|---|
| 0 | `0x000000` | `0x0FC00` | `0x00` | PCIR | legacy x86, plaintext |
| 1 | `0x00FC00` | `0x14E00` | `0x03` | PCIR | EFI image (compressed) |
| 2 | `0x024A00` | `0x006000` | `0xE0` | NPDS | `VN` extension A |
| 3 | `0x02AA00` | `0x6E400` | `0xE0` | NPDS | `VN` extension B, holds the ucode table |

The chain is **not** the PCI-spec walk: images 0/1 carry an NVIDIA PCI Data
Extension (`NPDE`) after the data structure, whose `SUBIMAGE_LEN` field
(at `NPDE+8`, 512-byte units) overrides the PCIR length, and whose byte at
`NPDE+10` overrides the "last image" bit. `tools/vbios_chain.py` implements the
same rules as `gpu-unlock-ada/kernel/gpu_unlock/vbios_610.c:expansion()`, and
both produce the same four images and `adjust = 0x24A00 − 0xFC00 = 0x14E00`.

Image 3 is 451,584 bytes and is where the FALCON_UCODE table lives
(`0x98CD8` = BIT pointer `0x83ED8` + `adjust`). The previous document listed
only three images; the fourth is the one that carries the firmware. Corrected
here.

---

## 2. Task A — the EFI/GOP image, decompressed

### 2.1 Container and compression

The image at `0x00FC00` is a UEFI PCI expansion-ROM image (UEFI spec 13.4.2),
**not** a raw compressed blob:

| Field | Offset | Value |
|---|---:|---|
| `0xAA55` signature | `+0x00` | `0xAA55` |
| InitializationSize | `+0x02` | 167 → 85,504 B |
| EfiSignature | `+0x04` | `0x0EF1` |
| EfiSubsystem | `+0x08` | 11 (boot-service driver) |
| EfiMachineType | `+0x0A` | `0x8664` (x86-64) |
| CompressionType | `+0x0C` | 1 (EFI standard compression) |
| EfiImageHeaderOffset | `+0x16` | `0x50` |
| PCIR offset | `+0x18` | `0x1C` |

At `+0x50` the payload header is `{u32 compressed = 85,393, u32 uncompressed =
164,144}` followed by the stream. **VERIFIED.**

Decompression used the standalone Tiano/EFI decompressor that ships with the
Ghidra `ghidra-firmware-utils` extension
(`src/efidecompress/c/efidecompress.c`, built with `-DCONFIG_UTIL`).
Output is **164,144 bytes**, exactly the declared size. **VERIFIED.**

### 2.2 The decompressed PE

| Property | Value |
|---|---|
| Format | PE32+, machine `0x8664` (x86-64), image base 0, entry RVA `0x308` |
| Subsystem | 11 (EFI boot-service driver) |
| SizeOfImage | `0x278E0` |
| Sections | `.text` VA `0x280` / `0x219EF`; `.data` `0x21C80`/`0x3358`; unnamed `0x24FE0`/`0x1668`; `.xdata` `0x26660`/`0xD84`; `.reloc` `0x27400`/`0x4D0` |
| Functions decompiled | **302** (Ghidra 12.2 headless, `DumpC.java`), 0 failures |
| PE SHA-256 | `47a1f08b2b1294ee83896246e60ddadc7ec1b0f5e0f872477ca4378b4c8a89bd` |
| `.text` SHA-256 | `cbac2ec7f6ed7b88…` (full value in the evidence JSON) |
| Compressed stream SHA-256 | `faa91ad6e312e1f49acd402d381d86c365b64bbd6aa1e9298eba541a0930d683` |

The PE is the same in **both** profiles: A and B decompress to the identical
164,144-byte image hash. **VERIFIED.**

### 2.3 What the driver does

* It is a standard UEFI driver: it uses `gBS` boot services, publishes an
  `EFI_DRIVER_BINDING_PROTOCOL` on the GPU handle, and contains the usual
  component-name machinery (`FUN_0000028c` calls `gBS+0x90` and `gBS+0x150`).
* Its only large MMIO offsets are `0x300000` (the VBIOS PROM window, eight
  uses) and — in one helper — a set of memory-size registers.
* **No FEAT/fuse speed-select reference.** A byte scan for every register in
  Appendix A finds nothing. An instruction-aware capstone scan over
  `0x800000..0x840000` finds exactly three operands: `0x800000` twice and
  `0x820C14` once.

### 2.4 The one `0x82xxxx` reference is VRAM sizing, not rate policy

At RVA `0xF4B8` the driver builds a six-entry stack array
`{0x90020C, 0x90420C, 0x90820C, 0x90C20C, 0x91020C, 0x91420C}`, reads a count
from `0x2243C` (`& 0x1F`), reads a presence bitmap from `0x820C14`, and for each
set bit reads `0x90020C + i*0x40000`, masks with `0x1FFFF` (128 KiB units) and
accumulates a size. **VERIFIED** at the instruction boundary
(`... mov dword ptr [rax-0x20], 0x90020c ... call qword ptr [rax+0x18]`).

Two consequences:

1. `0x820C14` is a *fuse-block* word used as a memory-partition presence mask.
   It is not a rate control, and its presence explains the earlier false lead:
   the legacy x86 image runs the same loop with a `0x4000` stride from the same
   base (`mov esi, 0x90020C; add esi, 0x4000`), which is what a misaligned
   32-bit decode turned into a fabricated `0x00820C14` "fuse write".
2. **The fuse/FEAT aperture is host-readable from UEFI before any OS driver
   loads.** The GOP driver reads a word in `0x0082xxxx` during POST. That is
   the mechanism the hardware protocol in `docs/07` relies on: a UEFI
   application or DXE driver can read the speed-select words at pre-OS time
   without a kernel driver and without writing anything. **INFERRED** from the
   access pattern (a private accessor taking a BAR0 offset and returning a
   value); the aperture is otherwise unreachable from that code.

### 2.5 Residual limitation

Ghidra's function discovery does not cover the helper at `0xF4B8` (it is reached
only through a relocation-populated function-pointer table at `0x22740`), so a
function-list-only review would have missed it. The instruction scan covered the
whole executable section, but it only proves *absence of the named constants*,
not absence of every possible access path (e.g. an offset computed from a table).
No such table was found. **VERIFIED for constants / INFERRED for completeness.**

---

## 3. Task B — Falcon ucode entries

The FALCON_UCODE table is at `0x98CD8` (version 1, header 6, stride 6, 16
entries, 7 populated). `adjust = 0x14E00`. `tools/ucode_classify.py` parses
every entry with the FALCON_UCODE_DESC V1/V2/V3 layouts and writes each image
out.

| # | App id | Meaning | Desc | Engine mask | ucode id | IMEM | DMEM | Sigs | IMEM entropy |
|---:|---:|---|---|---:|---:|---:|---:|---|---:|
| 0 | `0x01` | PRE_OS | legacy (60 B) | — | — | 39,720 | 1,540 | none | 6.78 |
| 5 | `0x07` | app 0x07 | legacy (60 B) | — | — | 64,768 | 108 | none | 6.57 |
| 6 | `0x08` | LS_UDE | legacy (60 B) | — | — | 62,224 | 35,920 | none | 6.72 |
| 8 | `0x45` | FWSEC_DBG | V3 (812 B) | `0x400` | 9 | 62,720 | 3,456 | 2 / `0x3` | 7.996 |
| 9 | `0x85` | FWSEC_PROD | V3 (812 B) | `0x400` | 9 | 62,720 | 3,456 | 2 / `0x3` | 7.996 |
| 10 | `0x49` | app 0x09 DBG | V3 (812 B) | `0x1` | 10 | 22,528 | 3,112 | 2 / `0x3` | 7.990 |
| 11 | `0x89` | app 0x09 PROD | V3 (812 B) | `0x1` | 10 | 22,528 | 3,112 | 2 / `0x3` | 7.990 |

App-id naming follows the table in `nv-uefi-unlocker` (AGENTS.md §7.3 and
`assets/src/vbios.rs`): `0x01=PRE_OS`, `0x05=FIRMWARE_SEC_LIC`, `0x08=LS_UDE`,
`0x45=FWSEC_DBG`, `0x85=FWSEC_PROD`; the high bits `0x40`/`0x80` are the
debug/production selector and the low six bits are the application id. Under
that rule `0x49`/`0x89` are the debug/production pair of application `0x09`.

### 3.1 The two FWSEC variants

`0x45` and `0x85` have **byte-identical descriptors** (same stored size, same
IMEM/DMEM geometry, same engine mask `0x400`, same ucode id 9, same two
signature slots with version mask `0x3`) and **different ciphertext**. Their
DMEM is plaintext and both carry the same build stamp `Oct 20 2022 09:12:55`,
the same interface header at offset 28 (`01 04 08 02` = version 1, header 4,
stride 8, 2 entries), and the same crypto-engine strings
(`NVRNG engine`, `NVPKA engine [RSA mode]`, `NVPKA engine [ECC mode]`,
`NIST_P-256`, `NIST_P-384`).

Image SHA-256, content span (66,176 B) and DMA-rounded span (66,304 B):

| Entry | content | DMA-rounded |
|---|---|---|
| `0x85` PROD | `a9dbe61166d858bec35b83837cf4652730b0125c79b65b17fd1824c80cec0103` | `6bbcb2fdffdd90bf548611242c0890300c0c45f3e65db12dff9d0a30abafd06e` |
| `0x45` DBG | `f013f9a50e69a183…` | `9987f038fd2a8925…` |

The previously published `6bbcb2fd…` hash is the **DMA-rounded** span (the
unlock module rounds the stored size up to 256 bytes); the content hash is
different. Both are recorded so either convention is reproducible. **VERIFIED.**

Interpretation, bounded by evidence: the pair is the same firmware built twice
for the two signature-selection paths the driver chooses between in debug and
production modes. The ROM does not say which slot is used at run time; that is
decided by the fuse version and the driver. **INFERRED.**

### 3.2 app `0x09` (`0x49`/`0x89`)

Same descriptor schema, engine mask `0x1`, ucode id 10, IMEM 22,528 B, DMEM
3,112 B, two signatures, encrypted IMEM (7.99), plaintext DMEM with the same
crypto strings and the build stamp `Aug  8 2022 10:34:45`, and the same
interface header `01 04 08 02` at offset 16. The pair differs in 23,431 bytes
(complete IMEM plus ~900 DMEM bytes), consistent with a debug/production rebuild.

**What is established:** it is an authenticated, encrypted crypto-support
firmware image bound to engine bit 0, with a two-entry host interface.
**What is not:** which engine bit 0 is, and what the two interface entries do.
No local source names application `0x09`. **UNKNOWN** — and deliberately not
guessed from the strings.

### 3.3 The plaintext images

Three entries are **not** encrypted, and Ghidra's Falcon v5 processor module
disassembles them at high coverage:

| Image | Entries | Instructions | Byte coverage |
|---|---:|---:|---:|
| PRE_OS (`0x01`) | 39,720 | 13,497 | **99.8 %** |
| LS_UDE (`0x08`) | 62,224 | 20,651 | **99.9 %** |
| app `0x07` | 64,768 | — | **0 %** from offset 0 (v4 and v5) |

`envydis -m falcon` reports ~74 % unknown on the same images because this
envytools build has no `fuc5` (Falcon v5) target; the Ghidra `falcon:LE:32:v5`
module is the correct decoder for Ada-era Falcon code. That is a tooling
correction worth recording: **do not use `envydis -m falcon` as evidence that an
Ada Falcon image is encrypted.**

* **PRE_OS** is code: it starts with `exit`, `clear_b16`, `ret`, a
  `mov r10,0x1`, then a normal push-heavy prologue. Its immediates include
  `0x80000000` masks and `0x8F1BBCDC`/`0x8F80600` (crypto constants).
* **LS_UDE** is code with 62 KB of IMEM and 36 KB of DMEM full of structured
  ASCII tables.
* **app `0x07`** does not decode from offset 0 under either Falcon v4 or v5 and
  shows no periodicity (best self-similarity 5 %). Its first bytes
  (`7a 04 00 f8 02 8d 64 00 00 bf d9 8f 04 01 00 f4 …`) repeat in a
  39-byte-ish pattern that neither decoder accepts. **Role UNKNOWN.** Do not
  call it code or data on entropy alone.

### 3.4 The plaintext firmware touches the fuse aperture — but not the rate words

All three plaintext images were scanned for every speed-select and fuse word in
Appendix A: **zero occurrences**. The same scan over the decompressed GOP PE:
zero. The legacy x86 image: zero.

One positive finding, in LS_UDE at RVA `0x15CF..0x15EF` (**VERIFIED** in the
Ghidra listing):

```asm
mov r14, 0x74
add_b32 r9, r0, r14
ld_b8 r9, D[r9+0x2]        ; DMEM flag
bra_b8 r9, 0x0, ne, 0x15e2
mov r15, 0x821304
lbra 0x15f3
0x15e2: mov r15, 0x8215ac
0x15e7: mov r9, 0x14000000
0x15ec: or r9, r15, r9
0x15ef: ld_b32 r14, D[r9]   ; read a 0x0082xxxx word
```

So **Falcon firmware in the option ROM does read fuse-block words** —
`0x821304` or `0x8215AC`, selected by a DMEM flag, through an aperture selected
by the constant `0x14000000`. It does not read `0x8207D4`/`0x8207D8`/`0x82059C`
or anything in `0x8238xx`. The two words it does read are not documented
locally; they are 3–4 KB past the speed-select fuses. **Role UNKNOWN**, but this
is the first direct evidence that the ROM's own firmware reads SKU/fuse data,
which is consistent with a hardware-derived policy model.

### 3.5 Cross-SKU check: the same firmware runs on a professional AD102

The repository now also holds an RTX 6000 Ada dump
(`6000-vbios/254385.rom`, SHA-256 `394677dc316e6259…`, PCIR device `10DE:26B1`,
VBIOS `95.02.59.00.09`). Same container layout, same `adjust = 0x14E00`, same
seven populated ucode entries. Comparing entry by entry
(`tools/cross_sku_compare.py`, output in `research/cross_sku_firmware.json`):

| Entry | IMEM bytes (4090 / 6000) | IMEM diff | DMEM diff | Image |
|---|---|---:|---:|---|
| PRE_OS | 39,720 / 39,720 | **0** | 29 | different |
| app `0x07` | 64,768 / 64,768 | **0** | **0** | **identical** |
| LS_UDE | 62,224 / 62,260 | 30,369 | 5,534 | different |
| FWSEC_DBG (`0x45`) | 62,720 / 62,720 | **0** | 33 | different |
| FWSEC_PROD (`0x85`) | 62,720 / 62,720 | **0** | 33 | different |
| app `0x09` DBG (`0x49`) | 22,528 / 22,528 | **0** | 33 | different |
| app `0x09` PROD (`0x89`) | 22,528 / 22,528 | **0** | 33 | different |

The FWSEC PROD **IMEM is byte-identical** on both cards —
`5db588b90a2941202d7ac8fc910ee7dab17660a3695e32f244d13d73071ba232` — and so is
the DMEM except for **33 bytes**:

* offset `0x0A`: the low byte of the PCI device id (`0x84` → `0xB1`);
* `0xAB4..0xAD3`: one 32-byte per-SKU binding value (not a plain SHA-256 of the
  DMEM; no digest of any candidate span matched).

The DSS/debug variants behave identically, and the GOP EFI image is also
byte-identical across the two SKUs (`47a1f08b…`). **VERIFIED.**

Interpretation, and it is a strong one: NVIDIA ships **one signed FWSEC binary**
plus a small plaintext per-SKU DMEM parameter block. The IMEM ciphertext being
identical means the same key, the same IV and the same plaintext; the signature
lives in the descriptor and covers the IMEM, so the DMEM can be parameterised
per board after signing.

Consequence: **the ROM firmware is not the differentiator between a 4090 and an
RTX 6000 Ada.** The only per-SKU differences in the security firmware are the
device id and a 32-byte binding value. The parts that *do* differ (LS_UDE:
30,369 bytes of IMEM, 5,534 of DMEM) are the display/memory firmware, which must
differ — 24 GB GDDR6X versus 48 GB GDDR6 with different memory vendors.

---

## 4. Task C — the performance/silent delta

### 4.1 Size and shape

Copy 1 differs between A and B in **1,448 bytes across 34 ranges**. The backup
copy differs in **102 bytes** — the profiles live in the active copy. Within one
dump, copy 1 and copy 2 differ from `0xD6C00` to the end. **VERIFIED.**

| Range | Bytes | What it is |
|---|---:|---|
| `0x08D`, `0x0CE`, `0x24E`, `0x438` | 1 each | board/InfoROM identity fields |
| `0x47C..0x48B` | 16 | info string |
| `0xFBFF` | 1 | legacy image byte |
| `0x8A87F..0x8A883`, `0x8A88A` | 6 | EFI-region padding/digest bytes |
| `0x96917..0x96921`, `0x9694A..0x96954`, `0x9697D..0x96987`, `0x969B0..0x969BA` | 16 | settings records |
| `0xDBE29`, `0xDBE43` | 2 | record fields |
| `0xDE368..0xDE4F3` | 8 × 32 | per-record integrity fields |
| `0xDFA48..0xDFEFF` | 1,148 in 7 runs | record digests + payload near the InfoROM end |

No difference falls inside the ucode region (`0x34BB0..0x73000`) and none inside
the decompressed GOP image: **FWSEC and the EFI driver are byte-identical across
profiles.** **VERIFIED.**

### 4.2 What the `0xDFA48..0xDFF00` area actually is

It is the tail of an **InfoROM / manufacturing-provisioning record area** that
runs from about `0xD5000` to `0xE0000` (the rest of the image after `0x98E00` is
`0xFF` fill). Evidence:

* ASCII at `0xDFA00`: `20b32iR44b`; at `0xDFA28`: a little-endian Unix
  timestamp `0x6398BD16` (2022-12-06); nearby records are headed by small
  length/type words.
* Provisioning strings elsewhere in the area: `128305msi`, `P87986R1`,
  `RKSL NVPartner Prod`, `RKSL NVInternal!`, `bigben.nvidia.com`,
  `NVIDIA Corp`.
  `bigben.nvidia.com` is NVIDIA's manufacturing/provisioning host, and `RKSL`
  strings name key slots, not tuning parameters.
* The A/B differences in this area are **32-byte high-entropy fields** followed
  by short payload runs. Eight more 32-byte fields change earlier, at
  `0xDE368`, `0xDE404`, `0xDE4A0`, `0xDE4D4`, `0xDEA1C`, `0xDED90`,
  `0xDF374`, `0xDF98C`.
* Those fields are **not** plain SHA-256 or MD5 of the preceding record:
  hashing every window of 32/48/64/96/128/192/256/384/512 bytes before every
  32-byte field in `0xD5000..0xE0000` produces zero matches. So the integrity
  field is keyed (HMAC/signature) or covers a range that is not contiguous in
  the image. **VERIFIED (no plain digest) / INFERRED (keyed integrity).**

Conclusion, stated narrowly: the performance/silent delta is board identity,
**power/thermal/tuning records and their integrity fields**, plus InfoROM
identity strings. Nothing in it names, writes or seeds a tensor rate. It is a
configuration area, not a rate-policy area. **VERIFIED for "no FEAT/fuse
reference" / INFERRED for "power/thermal tuning".**

### 4.3 Comparison with other MSI samples

Not done. TechPowerUp's VBIOS downloads are behind a bot wall from this host
(HTTP 403 for both the page-scrape and the direct `.rom` paths), so no second
authentic MSI 4090 image could be obtained during this pass. The comparison is
listed as a low-priority follow-up rather than claimed.

---

## 5. Task D — F1–F8, re-reviewed

| # | Previous statement | Status now | Revised wording |
|---|---|---|---|
| F1 | "No devinit script table exists; GPU bring-up is not in the option ROM." | **VERIFIED / revised** | No devinit *script table* exists (BIT `D` = 4 bytes, `I` = 36-byte NVINIT stub). The ROM does contain **plaintext Falcon firmware** (PRE_OS, app 0x07, LS_UDE) that can read fuse words; bring-up code is present as firmware, not as devinit scripts. |
| F2 | "The x86 image never references the FEAT/fuse-select registers." | **VERIFIED, extended** | Also true for the decompressed GOP PE and for all three plaintext Falcon images. Zero occurrences of any Appendix-A register in any plaintext region. |
| F3 | "The EFI image is compressed and is display code, not a rate source." | **VERIFIED** | It is a PE32+ x86-64 UEFI GOP driver (302 functions, `gBS`, driver binding). Its only `0x82xxxx` read is `0x820C14`, used for memory-partition sizing. |
| F4 | "FWSEC IMEM is encrypted." | **VERIFIED** | Entropy 7.996, 0 % zero bytes, and two independent copies (`0x45`/`0x85`) of the same geometry with different ciphertext. |
| F5 | "FWSEC is well-formed and matches the 1/4/8 interface." | **VERIFIED** | V3 descriptor, DMEM interface `01 04 08 02` at offset 28, signature-version mask `0x3`. |
| F6 | "Silent/performance differ by 1,448 bytes, none in ucode; FWSEC identical." | **VERIFIED, corrected** | 1,448 bytes in **34 ranges**; FWSEC **and** the GOP driver are identical. The `0xDFA48` area is a record area with per-record integrity fields, not one opaque 1.2 KB block. |
| F7 | "Two decompilers agree: 336 functions, identical port sets." | **VERIFIED (not re-run)** | Unchanged; the tooling report stands. |
| F8 | "angr cannot model 16-bit x86." | **VERIFIED (not re-run)** | Unchanged; `archinfo` still has no 16-bit x86. |

### Absolute claims replaced

| Old claim | Replacement |
|---|---|
| "The VBIOS cannot affect the restriction." | "No examined VBIOS region — legacy x86, decompressed GOP, three plaintext Falcon images, four signed descriptors — contains a speed-select write or a readable rate default. The VBIOS is therefore not a *demonstrated* source of that default. A side effect inside the encrypted FWSEC remains unobservable, and is not evidence either way." |
| "The VBIOS is only a supplier of signed firmware." | "The VBIOS supplies signed firmware **and consumes fuse data at boot** (LS_UDE reads `0x821304`/`0x8215AC`). It is a consumer of hardware configuration as well as a supplier of code." |
| "Persistence requires breaking SEC2 authentication." | "No authenticated, host-writable source of the rate default has been found. Persistence therefore requires either replaying the transient unlock before the driver binds, or a change inside the authenticated chain, which no evidence currently supports." |

---

## 6. What remains unknown

| Item | Why it matters | Status |
|---|---|---|
| Function of app `0x07` | 64 KB plaintext region that decodes under no Falcon ISA we have | UNKNOWN |
| Engine bit 0 / app `0x09` role | Bounds what the second crypto firmware does | UNKNOWN |
| Meaning of `0x821304` / `0x8215AC` | The only fuse words the ROM's firmware reads | UNKNOWN |
| Whether FWSEC reads or writes `0x8238xx` | Encrypted; unobservable statically | UNKNOWN, unobservable |
| Cold register state on this card | The whole fuse-origin question on hardware | Pending, see `docs/07` |
| Whether a pro AD102 carries different fuse words | Decides fuse vs firmware origin | Pending, see `docs/06` |

---

## 7. Reproduce

```bash
# 1. image chain + hashes
python3 tools/vbios_chain.py pc_extracted_files/bios_A_factory.rom --extract /tmp/imgs

# 2. EFI decompression (build the decompressor once)
curl -O https://raw.githubusercontent.com/al3xtjames/ghidra-firmware-utils/master/src/efidecompress/c/efidecompress.c
cc -O2 -DCONFIG_UTIL -o efi_decompress efidecompress.c
python3 tools/efi_extract.py pc_extracted_files/bios_A_factory.rom \
    --decompressor ./efi_decompress --outdir /tmp/efi --scan-range 800000:840000

# 3. Falcon ucode classification + image extraction
python3 tools/ucode_classify.py pc_extracted_files/bios_A_factory.rom \
    --json /tmp/ucodeA.json --outdir /tmp/ucodeA

# 4. Falcon coverage (Ghidra 12.2 + ghidra_falcon extension)
analyzeHeadless /tmp/gp falcon -import /tmp/ucodeA/ucode_01_02aa54.imem.bin \
    -processor "falcon:LE:32:v5" -loader BinaryLoader -loader-baseAddr 0 \
    -scriptPath tools/ghidra_scripts -postScript FalconCoverage.java 0 /tmp/preos.txt

# 5. every number in this document
python3 tools/static_evidence.py --out research/static_evidence.json
```
