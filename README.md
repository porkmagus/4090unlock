# 4090unlock

Firmware research on the RTX 4090 Tensor-Core rate unlock: what the volatile
unlock actually changes, what the board VBIOS does and does not control, and the
tooling required to analyze both.

**Start here:** [docs/FINDINGS.md](docs/FINDINGS.md) — the consolidated findings
(evidence, confidence labels, open questions, reproduction).

| Document | Contents |
|---|---|
| [docs/FINDINGS.md](docs/FINDINGS.md) | Comprehensive findings: artifacts, VBIOS anatomy, mechanism, evidence chain, tooling, next steps |
| [docs/01-vbios-unlock-cross-reference.md](docs/01-vbios-unlock-cross-reference.md) | VBIOS ↔ unlock cross-reference with offsets and entropy evidence |
| [docs/02-ghidra-kuna-vbios.md](docs/02-ghidra-kuna-vbios.md) | Ghidra vs Kuna on the 16-bit option ROM (336 functions, port-set agreement) |
| [docs/03-angr-and-plugins.md](docs/03-angr-and-plugins.md) | angr evaluation and plugin ports (AngryGhidra, angr-ghidra-core, firmware-utils) |
| [docs/04-plugin-landscape.md](docs/04-plugin-landscape.md) | Blocker → tool map, IDA catalog mining, Ghidra Falcon port |
| [RTX4090_Tensor_Unlock_Research.md](RTX4090_Tensor_Unlock_Research.md) | Original research brief |

**Artifacts:** `pc_extracted_files/` holds the two on-card dumps and their spec
sheets. **Nothing here was flashed or written to a GPU.**
