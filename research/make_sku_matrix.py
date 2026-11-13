#!/usr/bin/env python3
"""Generate research/ad102_sku_matrix.csv from sourced AD102 specifications.

Every number in SOURCES is quoted from a named document; the per-SM-per-clock
columns are computed here so the normalisation can be checked and re-run
instead of hand-copied. Nothing in this file is measured on our own card.

Normalisation: FLOP/s per SM per clock = TFLOPS * 1e12 / (SMs * boost_MHz * 1e6)

Why this file exists: raw TFLOPS cannot distinguish "bigger card" from
"different per-SM rate". Dividing by SM count and boost clock can, and that is
the whole question for the tensor-rate unlock.

Usage: python3 research/make_sku_matrix.py > research/ad102_sku_matrix.csv
"""
from __future__ import annotations

import csv
import sys

# TFLOPS / TOPS, dense (sparsity excluded) unless the field name says otherwise.
SKUS = [
    {
        "sku": "GeForce RTX 4090",
        "variant": "AD102-300-A1",
        "device_id": "10DE:2684",
        "subsystem_examples": "1462:5103 (MSI, this project's card)",
        "role": "consumer",
        "sm_count": 128,
        "cuda_cores": 16384,
        "boost_clock_mhz": 2520,
        "tgp_w": 450,
        "fp32_tflops": 82.6,
        "fp8_fp16acc": 660.6,
        "fp8_fp32acc": 330.3,
        "fp16_fp16acc": 330.3,
        "fp16_fp32acc": 165.2,
        "bf16_fp32acc": 165.2,
        "tf32": 82.6,
        "int8_tops": 660.6,
        "vbios_observed": "95.02.3C.40.B9 (perf) / .B8 (silent)",
        "fwsec_observed": "app 0x85 PROD, ucode_id 9, engine_mask 0x400, 2 sigs ver 0x3",
        "fwsec_prod_imem_sha256": "5db588b90a2941202d7ac8fc910ee7dab17660a3695e32f244d13d73071ba232",
        "source": "NVIDIA Ada GPU Architecture whitepaper v2.02, Appendix A (Table 2); card VBIOS from this repo's dumps",
        "confidence": "VERIFIED (whitepaper) + VERIFIED (dumps)",
    },
    {
        "sku": "GeForce RTX 4090 D",
        "variant": "AD102-250-A1",
        "device_id": "10DE:2685",
        "subsystem_examples": "China-market SKU",
        "role": "consumer",
        "sm_count": 114,
        "cuda_cores": 14592,
        "boost_clock_mhz": 2520,
        "tgp_w": 425,
        "fp32_tflops": 73.54,
        "fp8_fp16acc": 294.2,
        "fp8_fp32acc": None,
        # TechPowerUp quotes a single "FP16" figure. On the RTX 4090 page that
        # figure equals NVIDIA's FP32-accumulate rating (165.2), so the same
        # convention is assumed here and the FP16-accumulate column is left
        # blank rather than invented.
        "fp16_fp16acc": None,
        "fp16_fp32acc": 147.1,
        "bf16_fp32acc": 147.1,
        "tf32": 73.54,
        "int8_tops": 588.3,
        "vbios_observed": "not collected",
        "fwsec_observed": "not collected",
        "fwsec_prod_imem_sha256": None,
        "source": "TechPowerUp GPU database (observed table, derived from NVIDIA ratings)",
        "confidence": "OBSERVED (third-party); TPU states one FP16 figure, treated as the FP32-accumulate rating by analogy with its RTX 4090 page",
    },
    {
        "sku": "RTX 6000 Ada Generation",
        "variant": "AD102GL (PG133 SKU 510)",
        "device_id": "10DE:26B1",
        "subsystem_examples": "10DE:16A1",
        "role": "professional",
        "sm_count": 142,
        "cuda_cores": 18176,
        "boost_clock_mhz": 2505,
        "tgp_w": 300,
        "fp32_tflops": 91.1,
        "fp8_fp16acc": 728.5,
        "fp8_fp32acc": 728.5,
        "fp16_fp16acc": 364.2,
        "fp16_fp32acc": 364.2,
        "bf16_fp32acc": 364.2,
        "tf32": 182.1,
        "int8_tops": 728.5,
        "vbios_observed": "95.02.59.00.09 (TechPowerUp 276178, MD5 e68cb628e1572a1b29cf482c0b324828)",
        "fwsec_observed": "app 0x85 PROD, identical to the 4090 (IMEM bit-identical, DMEM 33 bytes differ)",
        "fwsec_prod_imem_sha256": "5db588b90a2941202d7ac8fc910ee7dab17660a3695e32f244d13d73071ba232",
        "source": "NVIDIA Ada Lovelace Professional GPU Architecture whitepaper v1.1, Appendix A (Table 2); VBIOS metadata from TechPowerUp VGA BIOS collection entry 276178",
        "confidence": "VERIFIED (whitepaper); VBIOS metadata OBSERVED",
    },
    {
        "sku": "NVIDIA L40",
        "variant": "AD102 (datacenter)",
        "device_id": "not collected",
        "subsystem_examples": "datacenter PCIe card",
        "role": "professional (datacenter)",
        "sm_count": 142,
        "cuda_cores": 18176,
        "boost_clock_mhz": 2490,  # derived: 90.5 TFLOPS / (18176 * 2) = 2.490 GHz
        "tgp_w": 300,
        "fp32_tflops": 90.5,
        "fp8_fp16acc": 362.0,
        "fp8_fp32acc": None,
        "fp16_fp16acc": 181.0,
        "fp16_fp32acc": None,
        "bf16_fp32acc": 181.0,
        "tf32": 90.5,
        "int8_tops": 362.0,
        "vbios_observed": "not collected",
        "fwsec_observed": "not collected",
        "fwsec_prod_imem_sha256": None,
        "source": "NVIDIA Ada GPU Architecture whitepaper v2.02, Appendix C (Table 4); boost clock derived from FP32 TFLOPS and CUDA core count",
        "confidence": "VERIFIED (whitepaper); accumulate type NOT stated by NVIDIA - the 2x gap to RTX 6000 Ada holds for INT8, which has no accumulate split",
    },
]


def per_sm_clk(tflops, sm, mhz):
    if tflops is None or not sm or not mhz:
        return None
    return round(tflops * 1e12 / (sm * mhz * 1e6), 1)


def main():
    cols = list(SKUS[0].keys()) + [
        "fp16_fp16acc_per_sm_clk", "fp16_fp32acc_per_sm_clk",
        "fp8_fp16acc_per_sm_clk", "fp8_fp32acc_per_sm_clk",
        "int8_per_sm_clk", "fp32acc_to_fp16acc_ratio",
        "fp16acc_rate_class", "fp32acc_rate_class", "notes",
    ]
    w = csv.DictWriter(sys.stdout, fieldnames=cols)
    w.writeheader()
    for s in SKUS:
        row = dict(s)
        row["fp16_fp16acc_per_sm_clk"] = per_sm_clk(s["fp16_fp16acc"], s["sm_count"], s["boost_clock_mhz"])
        row["fp16_fp32acc_per_sm_clk"] = per_sm_clk(s["fp16_fp32acc"], s["sm_count"], s["boost_clock_mhz"])
        row["fp8_fp16acc_per_sm_clk"] = per_sm_clk(s["fp8_fp16acc"], s["sm_count"], s["boost_clock_mhz"])
        row["fp8_fp32acc_per_sm_clk"] = per_sm_clk(s["fp8_fp32acc"], s["sm_count"], s["boost_clock_mhz"])
        row["int8_per_sm_clk"] = per_sm_clk(s["int8_tops"], s["sm_count"], s["boost_clock_mhz"])
        if s["fp16_fp16acc"] and s["fp16_fp32acc"]:
            row["fp32acc_to_fp16acc_ratio"] = round(s["fp16_fp32acc"] / s["fp16_fp16acc"], 3)
        else:
            row["fp32acc_to_fp16acc_ratio"] = None
        # Reference point: RTX 6000 Ada does 1024 FLOP/SM/clk with either
        # accumulate type; the RTX 4090 does 1024 only with FP16 accumulate and
        # 512 with FP32 accumulate. Classify each column separately.
        def klass(rate):
            if rate is None:
                return "unknown"
            if rate >= 900:
                return "full (1024 FLOP/SM/clk)"
            if rate >= 400:
                return "half (512 FLOP/SM/clk)"
            return "unexpected (%s)" % rate
        row["fp16acc_rate_class"] = klass(row["fp16_fp16acc_per_sm_clk"])
        row["fp32acc_rate_class"] = klass(row["fp16_fp32acc_per_sm_clk"])
        row["notes"] = s["confidence"]
        w.writerow(row)


if __name__ == "__main__":
    main()
