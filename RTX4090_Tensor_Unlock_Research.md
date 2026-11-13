# RTX 4090 Tensor Core Unlock & Firmware Persistence

**Firmware research / technical brief**

Windows UEFI unlockers, TechPowerUp ROM sources, NVFlash, Ghidra + Kuna research and dual-BIOS validation

**Version:** 1.0  |  **Research date:** November 12, 2026  |  **Scope:** Read-only research; no flash payload

> **PRIMARY HARDWARE FACTS:** Reported MSI GeForce RTX 4090, dual VBIOS, active VBIOS version 95.02.3C.40.B9. Exact MSI board SKU, PCI subsystem device ID, ROM SHA-256, and the second BIOS bank version have not yet been captured.


> **PRIMARY CONCLUSION:** Boot-time and UEFI-based volatile unlocks exist. I did not verify a public demonstration of on-card, cold-power-persistent modified firmware for Ada RTX 4090. NVFlash can write accepted VBIOS images; it does not automatically authenticate arbitrary code edits.


This document is designed as a reproducible research plan rather than an invitation to flash a mismatched ROM. Firmware operations can render a display adapter unbootable; motherboard firmware edits introduce separate motherboard-brick risks.

Status language throughout: VERIFIED SOURCE = documented by primary repository/vendor; REPORTED = author or issue evidence; HYPOTHESIS = needs testing; UNKNOWN = cannot be established from the current data.

## Contents

1. [Executive findings](#1-executive-findings-and-decision)
2. [System identity and VBIOS](#2-target-system-identity-what-is-known-and-missing)
3. [Relevant repositories](#3-relevant-repository-map)
4. [Unlock mechanism](#4-mechanism-what-the-unlock-actually-changes)
5. [Firmware downloads and provenance](#5-firmware-acquisition-and-provenance-catalog)
6. [Windows NVFlash backup procedure](#6-windows-collection-procedure-read-only-before-any-flash)
7. [Ghidra, Kuna and envytools](#7-ghidra--kuna--envytools-cross-reference-plan)
8. [Persistence hypotheses](#8-research-hypotheses-and-falsifiable-milestones)
9. [Benchmark matrix](#9-benchmark-and-rollback-test-matrix)
10. [Risks and stop conditions](#10-failure-modes-signing-boundaries-and-stop-conditions)
11. [Agent handoff](#11-agent-handoff-and-supplied-reproducibility-assets)
12. [Primary sources](#appendix-a-verified-and-reviewed-sources)

---

# 1. Executive findings and decision

| **Question**                                                  | **Finding**                                                                                                                          | **Confidence**                              |
|---------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------|
| Does an RTX 4090 Tensor-rate unlock exist?                    | Yes. Multiple independent Linux and UEFI paths alter protected register permissions and selector state. [S01-S06]                  | High                                        |
| Does an automatic Windows boot path exist?                    | Yes, experimental 4090 UEFI Windows project; author verified one system, not your exact setup. [S08-S09]                           | High on existence; limited on compatibility |
| Does that unlock survive full power loss?                     | No. Author explicitly describes it as volatile. Sleep may also reset it. [S08]                                                     | High                                        |
| Is a permanent, portable, on-card 4090 firmware patch public? | No publicly verified demonstration found in reviewed sources through 2026-11-12. Absence of evidence is not proof of impossibility.  | Limited search conclusion                   |
| Can Windows NVFlash apply a modified VBIOS?                   | It can read and flash supported accepted images. Arbitrary modified signed regions are a different problem. [S10,S20]              | High                                        |
| Is reported 95.02.3C.40.B9 available online?                  | No exact indexed, attributable downloadable match verified. Need local backup and proper board identification.                       | Search-limited                              |
| Does Kuna replace Ghidra?                                     | No. It can serve as an alternative decompiler backend for supported binaries; neither unlocks encrypted secure firmware. [S13-S14] | High                                        |

## Practical recommendation

1. Preserve both physical VBIOS banks first; hash and separately label each ROM. This is the irreplaceable starting sample.

2. Use a published, non-flashing UEFI path as the runtime control experiment only after source review and platform checks.

3. Build a firmware corpus with matching OEM ROMs and the exact pinned NVIDIA 610.43.03 boot/GSP assets.

4. Map selector write provenance, authentication boundaries, and where defaults are actually obtained before discussing candidate patches.

5. Do not write an experimental image to either bank until the security and recovery hypotheses have evidence.

# 2. Target system identity: what is known and missing

| **Attribute**                           | **Value / acquisition requirement**                                                                   |
|-----------------------------------------|-------------------------------------------------------------------------------------------------------|
| GPU                                     | MSI GeForce RTX 4090; model variant NOT identified (do not infer SUPRIM/Gaming Trio from VBIOS alone) |
| Current VBIOS, selected switch position | 95.02.3C.40.B9 (user-reported; not a ROM hash)                                                        |
| Second VBIOS switch position            | UNKNOWN until powered-off switch and fresh capture                                                    |
| CPU/motherboard                         | Reported Intel i9-14900K / MSI MAG Z790 TOMAHAWK WIFI; confirm actual motherboard revision/UEFI       |
| OS                                      | Windows 11 reported; capture build and display driver version                                         |
| Device ID                               | RTX 4090 typically NVIDIA 10DE:2684; confirm active device                                            |
| PCI subsystem                           | UNKNOWN; capture vendor and subsystem device IDs via GPU-Z / PnP hardware IDs                         |
| Board SKU / PCB / power connectors      | UNKNOWN; obtain exact retail model, serial/board identifiers privately                                |
| ROM-bank SHA-256                        | UNKNOWN for both ROMs; critical even if reported version strings match                                |

> **Critical identity rule:** Version text and GPU device ID alone do not make a VBIOS crossflash-compatible. Require exact card/PCB, subsystem ID, power/VRM, memory and display-out evidence. The same version family can contain multiple vendor- and board-specific ROMs.


## Why your reported VBIOS is a valuable sample

At the time of this research, no exact indexed, attributable public ROM for `95.02.3C.40.B9` was verified. Near-family 95.02.3C.40.* images exist on other RTX 4090 boards, but none should be treated as identical or safe to flash. For reversers, your own two ROM banks provide a stronger same-board comparison than a random public crossflash candidate.

TechPowerUp VGA BIOS Collection [S11] and GPU-Z [S12] are the primary catalog/UI starting points. Search by GPU, MSI manufacturer, known subsystem IDs, memory size, verified/unverified listing status, BIOS version and image hash. Unverified community uploads need additional scrutiny.

# 3. Relevant repository map

| **Repo**                                      | **Role**                                                      | **Evidence / caution**                                                                                |
|-----------------------------------------------|---------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
| Zagitta/gpu-unlock [S01]                    | Linux kernel pre-driver mechanism                             | Broad RTX 20/30/40 support claims; Ada experimental. Not portable Windows module.                     |
| JustAResearcher/gpu-unlock-ada [S02-S03]    | Ada extension, pinned firmware extraction, four-write payload | Critical technical provenance for AD102; pinned NVIDIA 610.43.03 inputs.                              |
| windows-GPU-UNLOCK/Windows-GPU-UNLOCK [S04] | Profile-gated Windows UEFI boot/handoff                       | Do not remove hardware protections to fit MSI Z790. Bench/host tests are not hardware validation.     |
| physicsdolphin/nv-uefi-unlocker [S05-S07]   | Cross-platform UEFI, protected-register readbacks             | Includes DXE/FFS idea; firmware embedding remains a proposal.                                         |
| MarvinFS/rtx4090-uefi [S08-S09]             | RTX 4090 Windows boot-entry auto-reapplication                | Verified on one MSI 4090 / ASRock X870E host; sleep relocks. Needs local validation.                  |
| PantACRO4life/gpu-unlock-4090-windows [S22] | Narrow MSI Suprim X + Z790 GODLIKE implementation             | Exact profile only; not generic for another MSI board or ROM.                                         |
| notfromstatefarm/nvflashk [S20]             | Crossflash of alternate signed VBIOS images                   | Board ID mismatch bypass is NOT arbitrary NVIDIA signature generation.                                |
| Panchovix/nvidia-vbios-vix-editor [S19]     | Offline VBIOS table inspection and edits                      | Edited ROMs use loader/override route; stock NVFlash cannot generally flash arbitrary unsigned edits. |

# 4. Mechanism: what the unlock actually changes

The public implementations execute a protected NVIDIA firmware path before the regular driver takes ownership. A boot-chain / Booter payload opens relevant privilege-level write permissions, then the host applies readback-checked performance selector overrides. The affected state is volatile, not an EEPROM change. [S03,S05,S06,S08]

| **Layer**                   | **Artifact / state**                                           | **Security and persistence boundary**                                 |
|-----------------------------|----------------------------------------------------------------|-----------------------------------------------------------------------|
| PCI option-ROM / VBIOS      | Legacy/UEFI images, board tables, signed FWSEC-related content | On-card SPI flash, but subregions may be signed/authenticated.        |
| SEC2 / FWSEC / Booter / GSP | Protected firmware chain, boot and management programs         | Authenticated code. Binary modification may invalidate signature.     |
| PLM permission registers    | WPR_CFG, FBPA, WPR, FEAT_OVR_PLM reported in Ada payload       | Temporary access gates. Not VBIOS offsets. [S03]                    |
| Rate selectors              | SS0 = 0x88888888; SS1 = 0x8 in successful 4090 logs            | Runtime GPU register state; may be lost on power transitions. [S08] |
| Windows/Linux NVIDIA driver | Normally follows the earlier register transaction              | May preserve state, reload/reset it, or see a power management reset. |

> **Important RE warning:** Searching for ASCII/hex 0x88888888 in a ROM is only a weak lead. The value could be assembled in code, encoded, stored elsewhere, derived from a fuse, or written by authenticated firmware. An observed runtime selector says nothing by itself about the location of a flashable default.


## Performance reality

The published 4090 peak MMA example is approximately 165 -> 329 TFLOP/s for targeted FP32-accumulate Tensor instructions. That is not an automatic 2x increase in AI applications. Power/clock limits, GPU occupancy, memory bandwidth, precision, CUDA library kernels and sampling steps frequently narrow gains. A reported MSI 4090 case reached selector readbacks but showed much smaller BF16/FP16 benefit, illustrating why verification requires real benchmarks. [S01,S08,S21]

# 5. Firmware acquisition and provenance catalog

| **Artifact source**                  | **Download or capture**                                     | **Purpose / constraints**                                                         |
|--------------------------------------|-------------------------------------------------------------|-----------------------------------------------------------------------------------|
| LOCAL / BIOS A                       | GPU-Z save-to-file and/or NVFlash --save                    | Authoritative original on-card ROM; retain unmodified forever.                    |
| LOCAL / BIOS B                       | Power off, change physical switch, capture independently    | Potential backup or alternate factory profile; verify distinct hash.              |
| TechPowerUp VGA BIOS [S11]         | Search NVIDIA > RTX 4090 > MSI, then exact identity       | Comparative ROM only until board IDs and hashes validated.                        |
| TechPowerUp NVFlash 5.867 [S10]    | Windows nvflash_5.867.zip                                   | Capture ROM and, in a separate approved phase, flash supported accepted ROMs.     |
| NVIDIA official 610.43.03 [S18]    | download.nvidia.com XFree86 driver archive / docs           | Ground-truth distribution of GSP code, depending on packaged archive.             |
| Pinned Ada unlock assets [S02-S03] | Pinned source archive + Arch/CachyOS package with checksums | booter_load_*, gsp_boot_*, descriptors, gsp_ga10x.bin, generated V67 payload. |
| UEFI loader binary [S05,S08]       | Source-built PE/COFF EFI application                        | An independently analyzable x86_64 executable, NOT original GPU secure firmware.  |
| NVIDIA open kernel module [S17]    | Version-matched sources                                     | Host-side paths, function/constant hints, firmware loading references.            |

The 610.43.03 firmware generation chain is documented with pinned inputs and output SHA-256. Do not silently substitute a different NVIDIA driver release because encrypted/authenticated images, offsets, and payload assumptions are version-sensitive. The newer UEFI repository FAQ records fallbacks from ephemeral CachyOS package retention to archival and first-party NVIDIA mirrors. [S03,S06]

## Pinned AD102 firmware file inventory

| **File (as used by pinned Ada work)** | **Origin / analysis role**                                                                                                    |
|---------------------------------------|-------------------------------------------------------------------------------------------------------------------------------|
| gsp_ga10x.bin                         | Signed NVIDIA GSP image, distributed in the pinned 610.43.03 driver/package; large protected firmware blob.                   |
| booter_load_ad102.bin                 | AD102 signed Booter loader asset extracted by project tooling from the pinned NVIDIA open-kernel-module source package.       |
| gsp_boot_ad102.bin                    | AD102 GSP boot code image derived via the pinned extraction script.                                                           |
| gsp_boot_desc_ad102.bin               | Boot descriptor/metadata related to the AD102 signed Booter sequence.                                                         |
| v67-ad102-610.43.03-four-plm.bin      | Locally generated research payload, not an official stock VBIOS image; opens four PLM permissions in reported implementation. |

Exact names and derivation are documented in [S03]. Treat the set above as the 610.43.03 reference corpus, not a guarantee that the installed driver version or your specific VBIOS contains byte-identical versions. The four NVIDIA-distributed inputs and generated payload do not create a flashable permanent ROM by themselves.

## TechPowerUp NVFlash download integrity

The TechPowerUp page lists Windows NVFlash v5.867 (2025-02-25), archive nvflash_5.867.zip, SHA-256 E158DA4A6F2138D2268452C6B5FA315C8FDEBE827D9E556FA52E310C448C38D4. Check again when downloading because versions can change. [S10]

```powershell
Get-FileHash .\downloads\nvflash_5.867.zip -Algorithm SHA256
```

# 6. Windows collection procedure: read-only before any flash

## Step 1 \| Capture system identity

Location: Windows 11 Administrator PowerShell. These commands query rather than write hardware state.

```powershell
nvidia-smi --query-gpu=name,pci.bus_id,pci.device_id,vbios_version,driver_version,power.limit --format=csv
Get-CimInstance Win32_VideoController | Select Name,PNPDeviceID,DriverVersion | Format-List
Get-CimInstance Win32_BaseBoard | Format-List Manufacturer,Product,Version
manage-bde -status C:
Confirm-SecureBootUEFI
```

Run the included scripts/Collect-RTX4090-Baseline.ps1 to collect the same metadata in a timestamped folder. It deliberately does not download, flash, reboot, or touch the UEFI boot order.

## Step 2 \| Download NVFlash and back up BIOS A

1. Obtain NVFlash from TechPowerUp [S10] and verify its listed SHA-256 on the archive. Unzip to a dedicated folder, e.g., C:\GPU-RE\tools\nvflash\\

2. With the computer powered on in the current BIOS switch position, use GPU-Z to record the BIOS version, subvendor and device identifiers and save the ROM. Alternatively use NVFlash read-only backup.

3. In Administrator PowerShell at the folder containing the actual extracted executable, list adapters. Substitute the executable name if the package supplies nvflash.exe rather than nvflash64.exe.

```powershell
.\nvflash64.exe --list
.\nvflash64.exe --save C:\GPU-RE\capture\bios_A_factory.rom
Get-FileHash C:\GPU-RE\capture\bios_A_factory.rom -Algorithm SHA256
```

4. Store the ROM, GPU-Z screenshot, NVFlash stdout, VBIOS string and physical switch label as a single evidence unit.

## Step 3 \| Back up BIOS B independently

1. Shut down completely, switch off the PSU, disconnect AC, and use the card manufacturer's instructions to move the physical VBIOS switch while unpowered.

2. Boot normally, confirm GPU identity again, and save bios_B_factory.rom using the same read-only method.

```powershell
.\nvflash64.exe --save C:\GPU-RE\capture\bios_B_factory.rom
Get-FileHash C:\GPU-RE\capture\bios_B_factory.rom -Algorithm SHA256
```

3. Compare sizes/hashes, not merely version labels. Archive off the PC. Revert the physical switch while fully powered off if desired.

> **Stop condition:** If either ROM cannot be read, the switch does not behave as expected, or the GPU/subsystem IDs are inconsistent, stop and resolve the hardware identity issue. A dual-BIOS switch reduces certain recovery risks but does not guarantee recovery after a bad flash.


## Step 4 \| What an eventual NVFlash operation would entail

TechPowerUp documents the command nvflash bios.rom [S10]. That is a write operation, not part of this initial runbook. Only after proving an image is the exact accepted match, preserving both originals, verifying recovery hardware and explicitly approving the risk would a separate flashing procedure be justified. Board-ID bypass tools such as nvflashk may allow crossflashing different NVIDIA-signed images, but they do not make arbitrary code edits valid. [S20]

```powershell
# REFERENCE ONLY - DO NOT RUN WITHOUT IMAGE VALIDATION AND RECOVERY PLAN:  
# .\nvflash64.exe exact_verified_vendor_image.rom
```

Avoid force-flash, protection-off and mismatch-bypass switches as exploratory steps. Never use a near-version TechPowerUp ROM as a “test patch” merely because a file is accepted by NVFlash.

# 7. Ghidra + Kuna + envytools cross-reference plan

## Tool assignment by artifact

| **Artifact**                                    | **Primary tool**                                    | **Cross-reference method**                                                                                     |
|-------------------------------------------------|-----------------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| RTX 4090 PCI VBIOS ROM                          | nvbios + Ghidra binary/option-ROM view              | Enumerate PCIR images, BIOS tables, GOP PE headers, FWSEC region. Map file offsets versus execution addresses. |
| UEFI GOP x86_64 image                           | Ghidra PE/COFF loader; optionally Kuna              | Imports, initialization calls, data flow; retain section and relocation mapping.                               |
| NVIDIA Linux host kernel modules / object files | Ghidra ELF loader, grep/ripgrep source              | Function names, firmware loading, register and mailbox constants.                                              |
| UEFI unlocker BOOTX64.EFI / UNLOCK4090.EFI      | Ghidra PE/COFF + Kuna GUI extension                 | Relate Rust source calls to runtime transaction, signature handoff and selector readback.                      |
| GSP/Booter/Falcon microcode blobs               | envydis / vendor ISA-aware decoder where applicable | Separate code/data/authenticated/encrypted areas; do not assume x86 or decompilable secure regions.            |
| VBIOS configuration fields                      | VBIOS Vix Editor, table decoders                    | Read-only inspection of power/voltage/memory fields; do not infer Tensor selector from unrelated power tables. |

## Kuna setup and scope [S13-S14]

1. Install a Ghidra version supported by the chosen Kuna release. As of this research, the release page documents a build for Ghidra 12.1.2; confirm release/current compatibility at download time.

2. Download the version-matched KunaDecompiler Ghidra extension ZIP from Noelo-Lab releases.

3. In Ghidra: File -> Install Extensions -> + -> choose ZIP -> restart. Then File -> Configure -> Miscellaneous -> enable KunaDecompilerPlugin.

4. Check the decompiler output for the Kuna version comment; compare against stock Ghidra output and source functions. Avoid automatic blind trust in either decompiler.

5. For agent workflows, run `kuna install-skill` from the supported installed Kuna CLI and direct agents to the specific decoded PE/ELF objects. The CLI supports `kuna decompile ...` and `kuna decompile-project ...` for supported executable formats.

Caveat: GUI plugin activation does not automatically apply to Ghidra headless workflows. Kuna documents a separate backend integration path for analyzeHeadless/PyGhidra, with careful backup and exact platform/version matching. Prefer GUI-side baseline first. [S13]

## Cross-reference landmarks: source to runtime to ROM

| **Anchor**                    | **Where to find it**                                             | **What would constitute evidence**                                                   |
|-------------------------------|------------------------------------------------------------------|--------------------------------------------------------------------------------------|
| AD102 recipe & PCI routing    | gpu-unlock source tree, recipes.c [S01]                        | Exact PCI and family selection; no unsupported card assumptions.                     |
| Four PLM writes               | Ada pinned firmware README and payload-generation source [S03] | Ordered WPR_CFG / FBPA / WPR / FEAT_OVR_PLM addresses and readback checks.           |
| SS0/SS1 write & check         | UEFI unlockers and Windows log code [S05,S08]                  | Selector register addresses and transaction order, with independently logged values. |
| FWSEC & signed Booter inputs  | Pinned 610.43.03 extraction scripts and VBIOS parser [S03,S05] | Provenance to precise file section and signature/authentication boundary.            |
| Actual factory default source | Comparative ROM/firmware + host driver analysis                  | Evidence whether value comes from VBIOS table, secure code or SKU/fuse path.         |
| Cold reset and driver handoff | UEFI log + NVIDIA driver + benchmarks                            | Whether selectors persist after FLR, sleep and full power removal.                   |

## Minimum cross-reference record

```text
source_repo,commit,file_line,artifact_sha256,file_offset,virtual_address,isa,register_name,register_address,mask,value,permission_stage,write_stage,verification,confidence
```

Never equate a file offset in a ROM, a microcontroller DMEM position, a GPU MMIO address, a PE virtual address or a PCI BAR aperture. They are different coordinate systems. Document transformations explicitly before creating byte patches.

# 8. Research hypotheses and falsifiable milestones

| **Hypothesis**                                           | **Evidence required**                                                                 | **Current state**                                 |
|----------------------------------------------------------|---------------------------------------------------------------------------------------|---------------------------------------------------|
| H1: writable VBIOS data determines default selectors     | Identify specific table, signedness, consumer code and post-flash cold-read behavior. | Open / unverified                                 |
| H2: signed GSP/Booter code establishes default           | Trace code/data loader and authentication chain to selectors.                         | Strong alternative / not confirmed as only source |
| H3: SKU fuse/strap determines capped default             | Tie source/read path to fuse/strap with controlled observed cold defaults.            | Open / unverified                                 |
| H4: pre-OS replay is the practical persistent experience | Boot every time, verify readbacks, benchmark; document sleep reset.                   | Existing projects demonstrate concept             |
| H5: motherboard DXE can reapply transparently            | OVMF test, signed motherboard firmware feasibility, test recovery.                    | Design study only; high risk                      |

## Phase gates

1. Gate 0: ROM A/B verified; logs, hashes, photos, filenames and hardware ID captured.

2. Gate 1: pinned firmware blob manifest generated without substitution or license violation.

3. Gate 2: source-level crosswalk identifies the exact selector write stage and protected permission chain.

4. Gate 3: comparative analysis establishes whether any mutable VBIOS field can alter factory defaults without invalidating authentication.

5. Gate 4: a candidate is reproducible on a separate development GPU and independently recoverable from corruption.

6. Gate 5: true permanence requires *power removed -> card moved to a different stock host -> full-rate reads and workload benchmark without loader*; anything short is automated replay.

# 9. Benchmark and rollback test matrix

| **Test**                               | **Required measurement**                                | **Interpretation**                             |
|----------------------------------------|---------------------------------------------------------|------------------------------------------------|
| Cold factory boot                      | SS0/SS1 baseline if possible; same CUDA build and model | Factory control point                          |
| UEFI unlock boot                       | UEFI transaction log, register readbacks, same tests    | Separate “unlock ran” from “model got faster”  |
| BF16/FP16 FP32-accumulate MMA          | Peak TFLOP/s, temperature/clock/power                   | Sensitive synthetic test; perhaps near 2x peak |
| TF32 cuBLAS GEMM                       | Matched clock/power, same shapes and libraries          | Often more useful measured throughput          |
| FP8 / INT8 controls                    | Same shapes/measurement path                            | Likely small/zero lift, control for confounds  |
| PyTorch workload (FLUX etc.)           | Fixed seeds, steps, resolution, precision, batch        | Real pipeline benefit may be lower than peak   |
| S3 sleep/hibernate/fast startup        | Readback and rerun exact workload                       | Determine relock windows                       |
| Warm restart vs complete AC power loss | Log state and results after each transition             | Do not confuse resume with cold reset          |

Initial tests should run at stock GPU clocks and stock power limits. Your known RTX 4090 undervolt should be temporarily disabled during reproducibility testing. Then reintroduce it with recorded GPU power/thermal monitoring, not as part of the initial proof.

# 10. Failure modes, signing boundaries and stop conditions

- The signed firmware chain may reject any modified Booter, FWSEC or GSP region. NVFlash being able to write a ROM does not imply the card will execute altered secure code.

- A valid NVIDIA-signed crossflash from another board can still misconfigure VRM, memory, cooler, connector layout, board power and display outputs. Dual BIOS is not a license to ignore hardware identity.

- Rewriting a motherboard UEFI volume to embed DXE code creates a different failure domain: Boot Guard, firmware rollback/ME interactions and possibly a non-booting motherboard. [S07]

- Disabling Secure Boot or editing the firmware boot order can trigger BitLocker recovery. Capture and safeguard the recovery key before any boot experiment. The pre-OS unlock itself is not a Windows executable replacement. [S08]

- Any unexpected GPU power or temperature spike, Xid fault, missing display, corrupted benchmark outputs, or register/readback disagreement stops active experiments until diagnosed.

- Production secure firmware segments may be encrypted. Failed or meaningless Ghidra/Kuna disassembly of random-looking bytes is not proof that no relevant code exists.

# 11. Agent handoff and supplied reproducibility assets

The accompanying research bundle ZIP includes a concise AGENT_HANDOFF.md with the target scope, immutable boundaries, source table, hypotheses and required output files. It also includes two read-only tools:

- scripts/Collect-RTX4090-Baseline.ps1 - system and boot-security metadata capture, no ROM flash or boot modification.

- scripts/firmware_corpus.py - SHA-256 manifest, simple ROM PCIR chain inventory, version strings, and CSV/JSON output; no firmware writes.

```powershell
python .\scripts\firmware_corpus.py --root C:\GPU-RE\corpus --out C:\GPU-RE\reports
```

The corpus tool is a triage utility, not a secure-boot validator or full NVIDIA VBIOS parser. ROM and firmware binaries are intentionally not bundled: the originals must be locally dumped or downloaded under applicable licenses and hash-verified.

# Appendix A. Verified and reviewed sources

- **S01 Zagitta / gpu-unlock**: <https://github.com/Zagitta/gpu-unlock>  
  Linux module, supported GPU and benchmark claims

- **S02 JustAResearcher / gpu-unlock-ada**: <https://github.com/JustAResearcher/gpu-unlock-ada>  
  Ada extension and pinned extraction chain

- **S03 Pinned 610.43.03 firmware README**: <https://github.com/JustAResearcher/gpu-unlock-ada/blob/main/firmware/README.md>  
  Booter/GSP firmware files and four-PLM payload provenance

- **S04 Windows-GPU-UNLOCK**: <https://github.com/windows-GPU-UNLOCK/Windows-GPU-UNLOCK>  
  Profile-gated experimental Windows UEFI implementation

- **S05 physicsdolphin / nv-uefi-unlocker**: <https://github.com/physicsdolphin/nv-uefi-unlocker>  
  Cross-platform pre-driver unlocker

- **S06 UEFI unlocker FAQ**: <https://github.com/physicsdolphin/nv-uefi-unlocker/blob/main/docs/faq.en.md>  
  Secure boot chain, firmware downloads and readbacks

- **S07 DXE/FFS feasibility study**: <https://github.com/physicsdolphin/nv-uefi-unlocker/blob/main/docs/dxe-driver-ffs-feasibility.md>  
  Proposed motherboard firmware embedding, unproven

- **S08 MarvinFS / rtx4090-uefi**: <https://github.com/MarvinFS/rtx4090-uefi>  
  Windows RTX 4090 automatic reapply, one-machine evidence

- **S09 RTX 4090 UEFI release page**: <https://github.com/MarvinFS/rtx4090-uefi/releases>  
  Public release, evidence scope and SHA-256

- **S10 TechPowerUp NVIDIA NVFlash**: <https://www.techpowerup.com/download/nvidia-nvflash/>  
  Windows flash utility version 5.867 and checksums

- **S11 TechPowerUp VGA BIOS collection**: <https://www.techpowerup.com/vgabios/>  
  Catalog to search, filter and verify candidate ROMs

- **S12 TechPowerUp GPU-Z**: <https://www.techpowerup.com/gpuz/>  
  Read-only GPU identity and ROM backup

- **S13 Noelo-Lab / Kuna**: <https://github.com/Noelo-Lab/kuna>  
  Rust decompiler, Ghidra extension and agent skill

- **S14 Kuna release page**: <https://github.com/Noelo-Lab/kuna/releases>  
  Ghidra-version-specific extension bundles

- **S15 Ghidra**: <https://github.com/NationalSecurityAgency/ghidra>  
  Structure and disassembly/decompilation environment

- **S16 envytools**: <https://github.com/envytools/envytools>  
  nvbios, envydis, rnndb, NVIDIA-specific tooling

- **S17 NVIDIA open GPU kernel modules**: <https://github.com/NVIDIA/open-gpu-kernel-modules>  
  Host-side driver and firmware interface reference

- **S18 NVIDIA GSP firmware chapter (610.43.03)**: <https://download.nvidia.com/XFree86/Linux-x86_64/610.43.03/README/gsp.html>  
  Official GSP documentation

- **S19 NVIDIA VBIOS Vix Editor**: <https://github.com/Panchovix/nvidia-vbios-vix-editor>  
  Offline Ada ROM table/field inspection and loader model

- **S20 nvflashk**: <https://github.com/notfromstatefarm/nvflashk>  
  Crossflash tool; NOT a signing bypass for arbitrary ROM edits

- **S21 MSI 4090 unlock issue \#304**: <https://github.com/Zagitta/gpu-unlock/issues/304>  
  Evidence that selector success need not mean 2x on every workload

- **S22 PantACRO4life Windows 4090 exact-profile port**: <https://github.com/PantACRO4life/gpu-unlock-4090-windows>  
  MSI Suprim X and Z790 GODLIKE exact-hardware proof

# Appendix B. Acquisition checklist / researcher fill-ins

| **Field**                                   | **Captured result**                                                                      |
|---------------------------------------------|------------------------------------------------------------------------------------------|
| GPU SKU / printed part number               | ____________________ |
| PCI NVIDIA device ID / subsystem ID         | ____________________ |
| Motherboard BIOS version                    | ____________________ |
| NVIDIA Windows driver version               | ____________________ |
| GPU-Z BIOS A version / SHA-256              | ____________________ |
| GPU-Z BIOS B version / SHA-256              | ____________________ |
| NVFlash exact ZIP SHA-256 validated?        | ____________________ |
| TechPowerUp candidate ROM URL (if any)      | ____________________ |
| Candidate ROM subsystem/board identity      | ____________________ |
| Pinned firmware artifacts SHA-256 verified? | ____________________ |
| UEFI unlock test approved?                  | ____________________ |
| Two-bank recovery tested?                   | ____________________ |

Final classification: CURRENTLY RECOMMENDED = complete backups, offline analysis, reproducible benchmark methodology. NOT YET RECOMMENDED = any on-card flash or motherboard firmware injection. Keep these tracks separate.
