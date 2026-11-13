# 4090unlock

Firmware research on the RTX 4090 Tensor-Core rate unlock: what the volatile
unlock actually changes, what the board VBIOS does and does not control, whether
the cap is a SKU policy rather than silicon, and the measurement system needed
to prove any of it.

**This repository contains no unlock payload, no flashing tool and no modified
firmware.** It is analysis, protocol and read-only capture tooling. Nothing here
was flashed or written to a GPU.

## Start here

| Document | What it answers |
|---|---|
| [docs/FINDINGS.md](docs/FINDINGS.md) | The consolidated picture: artifacts, VBIOS anatomy, mechanism, evidence chain |
| [docs/05-static-closure.md](docs/05-static-closure.md) | **New:** the EFI/GOP image decompressed, all seven Falcon ucode entries classified, the profile delta mapped, F1–F8 re-reviewed |
| [docs/06-ad102-cross-sku-policy.md](docs/06-ad102-cross-sku-policy.md) | **New:** consumer vs professional AD102, normalised per SM per clock — is the cap silicon or a setting? |
| [docs/07-windows-hardware-protocol.md](docs/07-windows-hardware-protocol.md) | **New:** how to read the factory register state safely (and why Windows can't) |
| [docs/08-acceptance-and-benchmarks.md](docs/08-acceptance-and-benchmarks.md) | **New:** three-gate acceptance system and the benchmark matrix |
| [docs/09-persistence-decision.md](docs/09-persistence-decision.md) | **New:** GO / NO-GO on every persistence route |
| [docs/10-public-field-data.md](docs/10-public-field-data.md) | **New:** what other people already measured — 15 Ampere cards, cold Ada probes, the vendor RM getter |

Background and earlier tooling work:

| Document | Contents |
|---|---|
| [docs/01-vbios-unlock-cross-reference.md](docs/01-vbios-unlock-cross-reference.md) | VBIOS ↔ unlock cross-reference with offsets and entropy evidence |
| [docs/02-ghidra-kuna-vbios.md](docs/02-ghidra-kuna-vbios.md) | Ghidra vs Kuna on the 16-bit option ROM |
| [docs/03-angr-and-plugins.md](docs/03-angr-and-plugins.md) | angr evaluation and plugin ports |
| [docs/04-plugin-landscape.md](docs/04-plugin-landscape.md) | Blocker → tool map, IDA catalog mining, Ghidra Falcon port |
| [RTX4090_Tensor_Unlock_Research.md](RTX4090_Tensor_Unlock_Research.md) | Original research brief |

## Research implications (short version)

1. **The VBIOS is not the source of the rate default.** Every readable region —
   legacy x86, the decompressed GOP driver, three plaintext Falcon images, four
   signed firmware descriptors — is now examined. None writes or reads the
   speed-select registers. The only `0x0082xxxx` access is a memory-size read.
2. **The cap is a per-SKU setting, not silicon.** The same AD102 die is sold at
   two tensor rates at the same SM count and clock (L40 vs RTX 6000 Ada), and
   the 4090 reaches the professional per-clock rate after two host register
   writes. Every FP32-accumulate tensor path on the 4090 is exactly half the
   FP16-accumulate rate; on the professional card they are equal.
3. **ROM firmware is not the differentiator — verified.** A second dump now in
   the repo (`6000-vbios/254385.rom`, RTX 6000 Ada) carries the **same FWSEC
   firmware bytes** as the 4090: the signed, encrypted IMEM is bit-identical and
   the plaintext DMEM differs in exactly 33 bytes (PCI device id plus one 32-byte
   per-SKU binding value). The GOP EFI driver is byte-identical too. Only the
   display/memory firmware (LS_UDE) differs, as it must.
4. **So the difference is in hardware.** Two software alternatives are now
   excluded: the ROM firmware is bit-identical, and cold Ada cards with no
   driver bound already show the reduced readout (`FEAT_READOUT_1 = 0x00410080`),
   which rules out host-side GSP-RM. On Ampere this was measured directly across
   15 cards: speed-select fuses `1` on every consumer GeForce, `0` on every
   professional/datacenter part. See `docs/10`.
5. **Persistence: no on-card route survives review.** A genuine on-card default
   would require a writable rate field (none exists) or a modified signed
   firmware (breaks SEC2). The ceiling is a host-dependent automatic pre-OS
   replay, which public projects already demonstrate.

## Artifacts

`pc_extracted_files/` holds the two on-card dumps and their spec sheets.

| | BIOS A — performance | BIOS B — silent |
|---|---|---|
| SHA-256 | `a4aade5a271fa793372da5f1196864b8918805465ba6cba31b0d09dc47619eae` | `15771e9243ae9ae673f2d662f610176cfabae4ccf457c70578f16b0ac26ea68f` |
| VBIOS | `95.02.3C.40.B9` | `95.02.3C.40.B8` |
| Board ID | `MSINV510MH.2W0` | `MSINV510MH.2X0` |

Both are 2,048,000-byte NVGI containers: `0x9400` header, two `0xE0000` VBIOS
copies, `0x2AC00` tail. The active copies differ by 1,448 bytes (34 ranges); the
backup copies by 102 bytes. FWSEC and the GOP driver are byte-identical across
profiles.

A third sample — `6000-vbios/254385.rom`, an RTX 6000 Ada (`10DE:26B1`,
subsystem `10DE:16A1`, VBIOS `95.02.59.00.09`, SHA-256 `394677dc316e6259…`) — is
the cross-SKU comparison target. Its FWSEC IMEM is **bit-identical** to the
4090's; only the display/memory firmware differs.

## Tools

All read-only. Tested offline against the dumps; nothing in this table touches
hardware except the two `tools/hw` capture scripts, which are procedures for a
future authorised run.

| Tool | What it does | Tested |
|---|---|---|
| `tools/vbios_chain.py` | NVGI container + PCIR/NPDE image chain, hashes, extraction | ✅ both dumps |
| `tools/efi_extract.py` | EFI expansion-ROM header, Tiano decompression, PE inventory, instruction-aware register scan | ✅ both dumps (identical PE) |
| `tools/ucode_classify.py` | FALCON_UCODE table, V1/V2/V3 descriptors, per-image entropy/DMEM strings | ✅ both dumps |
| `tools/cross_sku_compare.py` | Entry-by-entry firmware comparison between two dumps (IMEM/DMEM diffs) | ✅ 4090 vs 6000 and 4090 A vs B |
| `tools/fwsec_extract.py` | FWSEC descriptor + image (port of the public module's parser) | ✅ |
| `tools/static_evidence.py` | Recomputes every number quoted in `docs/05` | ✅ → `research/static_evidence.json` |
| `tools/hw/capture_linux.py` | Read-only BAR0 capture from a driverless Linux environment | ✅ synthetic sysfs tree |
| `tools/hw/decode_fingerprint.py` | Decodes `FEAT_READOUT_1`/SS0/SS1/fuses into a verdict | ✅ self-test + synthetic capture |
| `tools/hw/Collect-RTX4090-Baseline.ps1` | Windows identity/environment bundle (no MMIO) | ⚠️ not executed (no Windows host) |
| `bench/tensor_gates.py` | Three-gate acceptance harness (transaction, register state, performance) | ✅ self-test (GPU path not run) |
| `research/make_sku_matrix.py` | Generates `research/ad102_sku_matrix.csv` from sourced specs | ✅ |

```bash
# reproduce the static evidence
python3 tools/vbios_chain.py pc_extracted_files/bios_A_factory.rom
python3 tools/ucode_classify.py pc_extracted_files/bios_A_factory.rom --outdir /tmp/ucode
python3 tools/static_evidence.py --out research/static_evidence.json
python3 bench/tensor_gates.py --self-test
```

## Boundaries

* No flashing, fuse programming, Secure Boot change, or motherboard firmware
  modification is authorised in this project stage.
* Register reads are read-only and are the only hardware interaction the
  protocol in `docs/07` permits.
* Hardware tests are **PENDING AUTHORISATION**; nothing in this repository
  claims a hardware result that was not produced.
