# Plugin landscape for the VBIOS/Falcon blockers

**Scope:** research + ports only. No new VBIOS analysis was performed. Everything
below was checked against our stack: Ghidra 12.2, Kuna 1.997, angr 10.0.6,
Python 3.13.

---

## 1. Method

| Source | What it gave |
|---|---|
| `plugins.hex-rays.com` | The whole IDA catalog is public JSON: `https://hexrayssa.github.io/plugin-repository/plugins/combined.json` (269 plugins with keywords/descriptions/URLs). Filtered for firmware/UEFI/x86/symbolic — only 4 firmware-relevant entries. |
| `river-li/awesome-uefi-security` | UEFI tool map: efiXplorer, efiSeek, UEFITool, BIOSUtilities, fiano, Qiling EFI mode, efi_fuzz, tsffs, ebvm. |
| `PreOS-Security/awesome-firmware-security` | Platform-firmware background, BIOS/UEFI/ME/PSP primitives, testing talk. |
| `morluto/awesome-reverse-engineering` | Firmware/hardware + symbolic-execution sections: unblob, OFRAK, ripcord, QEMU, Triton, BINSEC, Qiling, Unicorn, Miasm, Remill. |
| GitHub search | `faucon`, `ghidra_falcon`, `dynamite`, `PcodeSym`, `symbolic-pcode`, `GhidraEmu`, `efiSeek`. |

**IDA catalog finding:** for this target the IDA side is exhausted — `efiXplorer`
(already ported into `porkmagus/ghidraplugins`), `fwhunt-ida` (rules, tool-independent),
`Binwalk`, and nothing for 16-bit real mode, GPU firmware, or Falcon.

## 2. Blocker → tooling map

| Blocker | Tool found | Status |
|---|---|---|
| 16-bit x86 decompilation | `ghidra-firmware-utils` `LegacyOptionROMLoader` | **ported + verified** (auto `x86:LE:16:Real Mode`, 82 fns) |
| 16-bit execution | Ghidra `EmulatorHelper` (p-code) | **proved**: 4 instructions of 16-bit p-code executed; stops at the `segment` userop (needs a `BreakCallBack`) |
| 16-bit p-code symbolic | `jdkleuver/PcodeSym`, `mnemonikr/symbolic-pcode` | assessed, not ported: PcodeSym drives angr over ghidra_bridge; symbolic-pcode is a Rust p-code engine |
| angr native 16-bit | — | **impossible today**: archinfo has no 16-bit x86 (proved earlier) |
| Encrypted Falcon firmware (static tooling) | `Thog/ghidra_falcon` (SLEIGH processor module) | **ported to Ghidra 12.2 + installed + language verified** |
| Falcon disassembly/emulation outside Ghidra | `vbe0201/faucon` (Rust: asm/disasm/emulator), `envytools/dynamite` (decompiler), `CAmadeus/falcon-tools` | assessed; not built yet |
| Compressed EFI image in the ROM | `ghidra-firmware-utils` UEFI loaders (FS loader handles hybrid/compressed option ROMs), `efiSeek`, UEFITool, `BIOSUtilities`, `uefi-firmware-parser`, Qiling EFI mode | extension installed; loaders not exercised on the ROM yet |
| VBIOS tables beyond old `nvbios` | `Panchovix/nvidia-vbios-vix-editor` (have), `platomav/BIOSUtilities`, `coderobe/VBiosFinder` | in place |
| Firmware extraction/repacking | `unblob`, `OFRAK`, `fiano` | available, not needed yet |

## 3. Ports performed this round

### 3.1 `ghidra_falcon` → Ghidra 12.2  ✅

The NVIDIA Falcon processor module had three breakages:

1. Gradle 9 removed `archivesBaseName` and the `baseName` Zip property:
   `archivesBaseName="Falcon"` → `base { archivesName = "Falcon" }`;
   `baseName "..."` → `archiveBaseName.set("...")`.
2. Gradle 9 removed `JavaExec.main` → `mainClass`.
3. Ghidra 12's loader API is `ImporterSettings`-based:
   `loadProgram(ByteProvider, String, Project, String, LoadSpec, List<Option>, MessageLog, Object, TaskMonitor)`
   → `loadProgram(ImporterSettings)` returning `List<Loaded<Program>>`, and
   `loadProgramInto(ByteProvider, LoadSpec, List<Option>, MessageLog, Program, TaskMonitor)`
   → `loadProgramInto(Program, ImporterSettings)`. `createProgram(provider, name, addr, ...)`
   → `createProgram(Address, ImporterSettings)`; the no-op `getDefaultOptions`/`validateOptions`
   overrides were dropped (their signatures moved).

Result: `dist/ghidra_falcon-1.1-Ghidra_12.2.zip`, installed; Ghidra imports with
`Using Language/Compiler: falcon:LE:32:v5:default`. The compiled `base_falcon.sla`,
`falcon.ldefs` and `envydis.sinc` are in the zip.

**What this buys:** any *plaintext* Falcon image (envytools test blobs, other
vendor firmware, or a decrypted FWSEC if that ever happens) can now be loaded,
disassembled and decompiled inside Ghidra — previously only `envydis` dead-listing.

### 3.2 `GhidraEmu` → Ghidra 12.2  ◐ partial

* JDOM: the plugin imported `org.jdom.Element`; Ghidra 12 ships JDOM **2**
  (`org.jdom2`). Import ported.
* Remaining: Ghidra 12 changed the ByteViewer API — `AddressInput.showAddressSpaceCombo`,
  `addChangeListener`, `getValue`, and `ByteViewerModel.{getGroupSize,setGroupSize,validateBytesPerLine}`
  are gone/renamed. 8 call sites need the new ByteViewer config API. Not needed for
  headless work; deferred.

### 3.3 Earlier in this investigation (for the record)

* `ghidra-firmware-utils`: `checkCanceled()` → `checkCancelled()` (Ghidra 12.2 GP-7104 purge). Built + installed + verified.
* `AngryGhidra`: builds unmodified on 12.2; Python driver ported to angr 10 (`from angr import claripy`, `ANGRYGHIDRA_PYTHON`).
* `angr-ghidra-core`: ported for angr 10 (`variable_kb` → `proj.kb.variables`, `sqlalchemy`); proved it misdecodes 16-bit (32-bit arch fallback), so it was reverted.

## 4. p-code execution proof (the angr replacement)

`tools/ghidra_scripts/EmuTrace.java` runs a function under `EmulatorHelper` and
logs every reached address. On `A_legacy_x86.bin` at `c000:05f8`:

```
0005f8
0005fa
0005fd
0005ff
000601
STOPPED: Unimplemented CALLOTHER pcodeop (segment), PC=0000:0601
```

The decoder is correct — those are exactly the four instructions before the
`call` (`xor ch,ch; shl al,2; or ch,al; xor bl,bl`). The stop is Ghidra's x86
SLEIGH asking the host to compute a segmented address. Registering a
`BreakCallBack` for the `segment` userop (`linear = seg<<4 + off`) makes the call
and the rest of the function runnable. That is a small, well-scoped addition and
is the correct base for any 16-bit symbolic/emulation work — **not** angr.

## 5. Recommendations, in order

1. **Add the `segment` userop callback to `EmuTrace`** (≈20 lines) and trace the
   ROM's real-mode init path. This gives concrete execution of 16-bit code with
   no new dependencies.
2. **Evaluate `PcodeSym`** with our Python: if it lifts via *Ghidra p-code* rather
   than angr's 32-bit arch, it becomes the symbolic engine for this ROM. If it
   calls `angr.Project` on a blob, it inherits the 16-bit limit and should be
   skipped.
3. **Finish the `GhidraEmu` ByteViewer port** only if a GUI emulator is wanted;
   headless `EmulatorHelper` covers the analysis need.
4. **Build `faucon`** when a plaintext Falcon target appears; it is the only
   independent Falcon emulator (useful for validating Ghidra's SLEIGH semantics).
5. The encrypted FWSEC itself remains out of reach: SEC2 decryption, not a plugin
   problem. The new Ghidra Falcon language changes what is analyzable *after* a
   plaintext image exists, not whether one can be obtained.

## 6. Environment state

| Extension / tool | State |
|---|---|
| `ghidra-firmware-utils` | installed in Ghidra 12.2 (rebuilt for 12.2) |
| `AngryGhidra` | installed in 12.2 (set `ANGRYGHIDRA_PYTHON` to an angr venv) |
| `ghidra_falcon` | **installed in 12.2**, `falcon:LE:32:v4/v5` language loads |
| `GhidraEmu` | patched source, does not compile yet (ByteViewer API) |
| `PcodeSym`, `symbolic-pcode`, `faucon`, `dynamite` | cloned under `repos/`, not built |
| angr venv | `.venv-angr` (angr 10.0.6), `.venv-miasm` (unused) |

## 7. Reproduce

```bash
# IDA catalog (all 269 plugins, machine-readable)
curl -sL https://hexrayssa.github.io/plugin-repository/plugins/combined.json | jq '.plugins | length'

# Falcon module for 12.2
cd repos/ghidra_falcon && GHIDRA_INSTALL_DIR=~/Applications/ghidra_12.2_PUBLIC \
  ~/Applications/ghidra_12.2_PUBLIC/support/gradle/gradlew --no-daemon && unzip -o dist/*.zip -d ~/Applications/ghidra_12.2_PUBLIC/Ghidra/Extensions/

# p-code execution proof
analyzeHeadless /tmp/p emu -import roms/A_legacy_x86.bin -loader LegacyOptionROMLoader \
  -scriptPath tools/ghidra_scripts -postScript EmuTrace.java 0xc05f8 2000 /tmp/trace.txt
```
