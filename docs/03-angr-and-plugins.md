# angr and plugin research for the VBIOS target

**Scope:** static/offline on macOS. The target is the 4090 option ROM already in
`roms/`. No GPU was touched. Goal: find angr/Ghidra/Kuna tooling that adds real
capability here, port anything that doesn't match our Ghidra 12.2 / angr 10 /
Kuna 1.997 stack, and report what is actually usable versus theoretical.

---

## 1. Short answer

| Tool | Verdict |
|---|---|
| **Ghidra + `ghidra-firmware-utils`** | **Winner.** A real PCI option-ROM loader, ported with a one-line API fix, auto-selects `x86:LE:16:Real Mode`, defines the ROM headers and decompiled 82 functions. |
| Kuna (already installed) | Still the best 16-bit *decompiler* here: 338 functions, 100% port-set agreement with Ghidra. |
| **angr (standalone)** | **Cannot model this target.** archinfo has no 16-bit x86 architecture; a blob loads as 32-bit. |
| **angr-ghidra-core** | Runs after a port, but maps 16-bit to angr's 32-bit arch and **misdecodes**: proved below. Not trustworthy for this ROM. |
| **AngryGhidra** | Builds unmodified for Ghidra 12.2; Python driver needed an angr-10 port; works (verified on a 32-bit control). Useless on the 16-bit image for the same angr reason. |
| Miasm | 0.1.5's disassembler is `NotImplementedError: not fully functional` — dead end. |

## 2. Repositories reviewed

| Repo | ★ | Last push | Role | Ghidra/angr match |
|---|---:|---|---|---|
| `al3xtjames/ghidra-firmware-utils` | 510 | 2026-11-04 | PCI option-ROM + UEFI/FFS/TE loaders, UEFI data types | Ghidra 12.0+ → **one fix for 12.2** |
| `Nalen98/AngryGhidra` | 624 | 2026-11-03 | angr symbolic execution inside Ghidra | builds on 12.2 unmodified; **Python driver needs angr-10 port** |
| `angr/angr-ghidra-core` | 0 | 2026-09-17 | angr decompiler as Ghidra's `decompile` drop-in | installed on 12.1.4; **needs angr-10 API port + sqlalchemy** |
| `envytools` (already built) | — | — | BIT/devinit decoding, `envydis` | works on case-sensitive volume |

No dedicated Ghidra VBIOS loader exists; `ghidra-firmware-utils` is the closest
and is the correct one.

## 3. Ports performed

### 3.1 `ghidra-firmware-utils` → Ghidra 12.2

Ghidra 12.2 removed the `checkCanceled`/`clearCanceled` spellings (GP-7104).
Two call sites failed to compile:

```diff
- monitor.checkCanceled();
+ monitor.checkCancelled();
```

(`src/main/java/firmware/cbfs/CBFSFileSystem.java:57`,
`src/main/java/firmware/uefi_fv/UEFIFirmwareVolumeHeader.java:107`)

Build: `./gradlew` with `GHIDRA_INSTALL_DIR` → `dist/ghidra_12.2_PUBLIC_20261112_ghidra-firmware-utils.zip`, installed to
`Ghidra/Extensions/ghidra-firmware-utils`. Verified headless:

```
INFO  Using Loader: x86 PCI Option ROM
INFO  Using Language/Compiler: x86:LE:16:Real Mode:default
INFO  DumpC.java> decompiled ok=82 failed=0
```

This replaces hand-rolled raw-binary imports: the loader sets the 16-bit language
automatically, defines the option-ROM headers and the entry point.

### 3.2 AngryGhidra → Ghidra 12.2 + angr 10

* Java side: **compiled unmodified** against 12.2 (`gradlew` → zip → installed).
* Python side (`angryghidra_script/angryghidra.py`) needed two changes:
  1. `import claripy` → `from angr import claripy` — angr 10 ships its own
     claripy; the standalone PyPI package downgraded z3 and broke
     `angr/rustylib.abi3.so` (`Library not loaded: @rpath/libz3.dylib`).
  2. Interpreter resolution: added `ANGRYGHIDRA_PYTHON`, and fixed inverted
     logic — the old code only tried `python` when `python3` had *succeeded*.
* Verified on a 32-bit control blob (`mov eax,0; cmp; je; ret`): the explorer
  returned the expected block trace `t:0x400000 t:0x400005 t:0x400008`.

### 3.3 `angr-ghidra-core` → angr 10 (tested in Ghidra 12.1.4, then reverted)

Installed with the bundled script (launcher replaces the `decompile` binary,
original backed up). Two blockers found and fixed:

1. **`sqlalchemy` missing** — the core's image cache imports `angr.angrdb`,
   which raises unless SQLAlchemy is installed. `uv pip install sqlalchemy`.
2. **angr 10 API removal** — angr 10 removed the `variable_kb` parameter:

   ```
   TypeError: Decompiler.__init__() got an unexpected keyword argument 'variable_kb'
   ```

   Ported to `proj.kb.variables` (three call sites in `angr_core.py`):
   `variable_kb=vkb` dropped from both `Decompiler(...)` calls, and
   `vkb.variables[entry]` → `proj.kb.variables[entry]`.

Result: 54/84 functions "decompiled", 30 raised `angr produced no code`.
**But the output is wrong**, see §5.

## 4. angr cannot model 16-bit x86

Standalone proof:

```python
import archinfo
archinfo.arch_from_id("x86:16")     # -> <Arch X86 (LE)>, bits 32
angr.Project(rom, main_opts={'backend':'blob','arch':'x86','base_addr':0xc0000})
# -> loaded as Arch X86, bits 32
```

`archinfo` exposes only `ArchX86` (32-bit); there is no 16-bit x86. The angr
decompiler core confirms the consequence: `_resolve_arch()` detects `"x86"` from
the presence of `EAX` and calls `archinfo.arch_from_id("x86", bits=16)`, which
returns the 32-bit arch.

Ground truth vs angr output for `c000:05f8`:

```asm
; true 16-bit decode (capstone)
0c05f8: 32 ed      xor ch, ch
0c05fa: c0 e0 02   shl al, 2
0c05fd: 0a e8      or ch, al
0c05ff: 32 db      xor bl, bl
0c0601: e8 a5 00   call 0xc06a9      <-- relative 16-bit call
0c0604: c3         ret
```

```
// angr-ghidra-core output
v6 = sub_66cf06ab();        <-- 32-bit rel32 decode of the same bytes
```

`0x66cf06ab` is what a 32-bit decoder makes of `e8 a5 00 ...`; the target is
wrong, so the 54 "successes" are unusable for this image. Fixing this is not a
version match: it needs a 16-bit x86 architecture in archinfo plus segmented
addressing in the decompiler model (real-mode `seg:off`, far calls/returns).

**Practical consequence:** angr (and AngryGhidra) are viable for 32-bit
protected-mode fragments or the decompressed EFI image, not for the real-mode
option-ROM image.

## 5. Miasm

Installed 0.1.5 (pure Python). Its disassembler cannot be driven through the
public API in this release:

```
miasm/arch/x86/disasm.py -> dis_instr(...) -> NotImplementedError: not fully functional
```

Not usable without patching the library; recorded as a dead end rather than a
recommendation.

## 6. What this means for the VBIOS investigation

The static answer does not change: the option-ROM code touches VGA and PCI
config space only, and never references the FEAT/fuse-select registers
(`docs/01`, `docs/02`). What changed is the *tooling*:

| Job | Best tool now |
|---|---|
| Load/decompile the 16-bit ROM | `LegacyOptionROMLoader` + Ghidra 12.2, or Kuna `--raw-image` |
| Cross-check decompiler output | Kuna vs Ghidra (100% agreement on I/O ports) |
| VBIOS table/FWSEC parsing | `nvbios` + `tools/fwsec_extract.py` |
| Symbolic execution | **not available** for 16-bit real mode in angr today |
| 32-bit protected-mode / EFI fragments | angr or AngryGhidra, after `ANGRYGHIDRA_PYTHON` is set |

## 7. Environment changes left in place

| Change | State |
|---|---|
| `ghidra-firmware-utils` 12.2 extension | installed in Ghidra 12.2 |
| `AngryGhidra` 12.2 extension | built + installed (set `ANGRYGHIDRA_PYTHON` to the angr venv before use) |
| angr venv | `~/porkmagusrepos/4090unlock-research/.venv-angr` (angr 10.0.6, pypcode 4.0.1, z3 5.3.3.0) |
| Ghidra 12.1.4 decompiler | **restored native**; angr-core experiment reverted |
| miasm venv | `.venv-miasm`, unused |

Known environment quirk: angr logs `failed loading "unicornlib.dylib"` on this
Python 3.13/macOS build; symbolic execution (VEX) still works, concrete
unicorn-backed helpers do not.

## 8. Reproduce

```bash
# option-ROM loader (Ghidra 12.2)
analyzeHeadless /tmp/p 4090 -import roms/A_legacy_x86.bin \
  -loader LegacyOptionROMLoader -scriptPath tools/ghidra_scripts \
  -postScript DumpC.java out.c

# AngryGhidra engine (angr 10), 32-bit control
ANGRYGHIDRA_PYTHON=$PWD/.venv-angr/bin/python \
  .venv-angr/bin/python repos/AngryGhidra/angryghidra_script/angryghidra.py /tmp/angry.json

# angr arch check
python -c "import archinfo; print(archinfo.arch_from_id('x86:16').bits)"
```
