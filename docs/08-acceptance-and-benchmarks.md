# Acceptance system and benchmarks: three gates

**Status:** design + tested harness. No GPU run in this stage.
**Why this document exists:** the project has already produced the failure mode
it needs to avoid — a selector readback that looked perfect while the workload
gained almost nothing, and conversely benchmark noise read as a win. A
successful register write is not a full-rate configuration, and a faster kernel
is not necessarily a tensor-rate change.

The acceptance system has three gates. Each gate has its own evidence and its
own pass condition. **No gate can be inferred from another.**

```
Gate 1  firmware transaction   →  the signed sequence ran and permissions opened
Gate 2  effective hardware state →  the hardware says all nine units are full rate
Gate 3  measured performance   →  the rate change is visible per clock, in the right paths
```

Harness: `bench/tensor_gates.py` (`--self-test` passes on synthetic data; see §8).

---

## 1. Gate 1 — firmware transaction

**Question:** did the intended signed firmware sequence execute?

**Evidence:** the unlocker's transaction log, which must contain, in order:

| Event | What to look for | Why |
|---|---|---|
| Payload copy | the V67 payload DMA'd into SEC2 DMEM, copy verified before start | proves the payload reached the engine |
| Marker | `0x67B00001` in the SEC2 mailbox | proves the ROP chain executed |
| HALT | SEC2 `CPUCTL` bit 4 set | proves the payload finished rather than faulted |
| `WPR_CFG` | `0x001FA7CC` → `0xFFFFF0FF` | first permission opened |
| `FBPA` | `0x009A0148` → `0xFFFFFF0F` observed (non-fatal if unchanged) | documented as an observation only |
| `WPR` | `0x001FA7C4` → `0xFFFFFFFF` | second permission |
| `FEAT` | `0x00823804` → `0xFFFFFFFF` | the gate that matters for the selector |

**Pass:** marker **and** HALT **and** at least `WPR_CFG`, `WPR`, `FEAT` at the
expected values.

**Known trap:** the Booter can report error `0x31` after the writes have already
happened. The write is proven by readback, not by the Booter's return code.

---

## 2. Gate 2 — effective hardware state

**Question:** is the hardware actually in a full-rate tensor configuration?

**Evidence:** a read-only capture of the register set in `docs/07` §2, taken
after the transaction, decoded by `tools/hw/decode_fingerprint.py`.

**Pass conditions (all required):**

| Check | Required value |
|---|---|
| `FEAT_READOUT_1` (`0x00823818`) | `0x00000000` — all nine 3-bit fields zero |
| `FEAT_OVR_SM_SPD` (`0x0082381C`) | `0x88888888` |
| `FEAT_OVR_SM_SPD_1` (`0x00823820`) | `0x00000008` |
| `FEAT_OVR_PLM` (`0x00823804`) | `0xFFFFFFFF` |
| `PMC_BOOT_0` (`0x00000000`) | not `0xBADF…` (device still accessible) |
| Readout stability | two reads 100 ms apart identical |

**Fail:** any non-zero readout field, or SS0/SS1 not at the unlock values, or an
inaccessible device.

**Why the readout is the criterion and SS0 is not:** SS0/SS1 record an *intent*
to override. `FEAT_READOUT_1` records what the SM units are actually doing. A
card can hold `0x88888888` in SS0 and still report a reduced readout if the
override is masked or the unit is in reset.

**Cross-check (recommended):** `FECS_FEAT_READOUT_1` (`0x00409668`) should agree
with the SM-side readout. If they disagree, stop and diagnose; one of them is
stale.

---

## 3. Gate 3 — measured performance

**Question:** does the effective rate change show up as throughput, in the paths
it should, at the same clock?

### 3.1 Measurement matrix

| # | Kernel | How to produce | Expected effect of the unlock |
|---|---|---|---|
| 1 | FP16 GEMM, **FP32 accumulate** | `torch.matmul` on `float16` with `allow_fp16_reduced_precision_reduction = False` (cuBLAS compute type 32F) | **≈ 2× per clock** |
| 2 | BF16 GEMM, FP32 accumulate | `torch.matmul` on `bfloat16` | **≈ 2× per clock** |
| 3 | TF32 GEMM | `float32` with `allow_tf32 = True` | **≈ 2× per clock** |
| 4 | FP32 pedantic GEMM | `float32` with `allow_tf32 = False` | **unchanged** (control) |
| 5 | INT8 GEMM | `torch._int_mm` | **unchanged** (control) |
| 6 | FP8 GEMM | `torch._scaled_mm` (optional; not all builds) | unchanged or ~2× depending on which unit carries FP8 — this is exactly what the run should *discover*, not assume |
| 7 | cuBLASLt explicit algorithm | `cublasLtMatmul` with `CUBLAS_COMPUTE_16F` vs `CUBLAS_COMPUTE_32F` | isolates the accumulate path without PyTorch's heuristics |
| 8 | Triton matmul | a fixed `tl.dot` kernel, `input_precision="ieee"` vs `"tf32"` | shows whether the effect survives a non-cuBLAS code path |
| 9 | Real workload | a fixed diffusion or LLM prefill step, same seed/steps/resolution | application-level gain, expected 10–34 %, not 2× |

Kernels 1–3 are the *signal*; 4–5 are the *controls*. A run where the controls
move as much as the signal is a measurement artifact, not an unlock.

### 3.2 Normalisation

Report **TFLOPS and TFLOPS per GHz of measured SM clock**:

```
TFLOPS_per_GHz = TFLOPS / (median SM clock during the run / 1000)
```

The unlock changes the instruction rate, not the clock. The 4090 is
power-limited in exactly these kernels, so absolute TFLOPS rises less than the
per-clock rate (community reports: 2.00× per clock, 10–34 % absolute at 450 W).
Per-clock is the correct primary metric; absolute TFLOPS is the practical one.

Also record for every run: driver version, CUDA version, torch version, kernel
names/shape, GPU temperature, power draw, power limit, throttle reasons, and the
number of iterations.

### 3.3 Protocol

1. Fresh boot, no other GPU work, no undervolt (baseline condition).
2. `nvidia-smi` sampling thread every 0.5 s for clocks/power/temperature.
3. 5 warm-up iterations, then 20 measured iterations; report **median**, plus
   min/max and the interquartile range.
4. Two independent processes per condition; if the medians differ by more than
   3 %, run a third.
5. Baseline and unlocked runs must use the same shapes, dtypes, seeds and
   library versions.
6. Record the *order* of runs. If stock runs before and after the unlock differ,
   something else changed (thermal, driver, background load).

### 3.4 Decision rules

| Kernel class | Pass | Fail |
|---|---|---|
| FP16-FP32acc, BF16-FP32acc, TF32 | ≥ **+40 %** per-clock, and absolute ≥ **+10 %** | < +20 % per-clock |
| FP32 pedantic, INT8 | within **± 8 %** | > ± 15 % |
| Real workload | ≥ **+10 %** end-to-end | no change, or slower |

Between 20 % and 40 % is **INCONCLUSIVE**: rerun with cuBLASLt explicit
algorithms before drawing a conclusion.

### 3.5 Confounds and how to separate them

| Confound | Symptom | Control |
|---|---|---|
| Power/thermal limit | absolute gain far below per-clock gain; clocks drop after unlock | report per-clock; sweep the power limit as a separate condition |
| Memory bandwidth | large-shape GEMM flat while small shapes gain | include a shape whose arithmetic intensity is high (e.g. 16384×16384×4096) |
| Kernel selection | one shape gains 2×, another nothing | force algorithms with cuBLASLt; check `CUBLASLT_LOG_*` |
| Clock boost behaviour | both stock and unlocked drift | per-clock normalisation + interleaved A/B/A runs |
| ECC / memory clocks | small consistent offset | record memory clock and ECC state |
| Different binary | Triton/cuBLAS pick different kernels after a driver change | pin driver and library versions; same binary for both conditions |

---

## 4. What each gate can and cannot prove

| Gate | Proves | Does not prove |
|---|---|---|
| 1 | the signed sequence executed | that the hardware changed |
| 2 | the hardware reports full rate | that any workload benefits |
| 3 | a workload benefits at the same clock | that the benefit comes from the tensor rate (hence the controls) |

Only all three together support the claim "the unlock produced a full-rate
tensor configuration that a real workload can use".

---

## 5. Baseline capture (stock)

Before any unlock, capture on the same card:

* Gate 2 at S0 and S2 (`docs/07`), for both BIOS positions.
* Gate 3 with the matrix above, at stock clocks and stock power limit.
* The identity bundle from `tools/hw/Collect-RTX4090-Baseline.ps1`.

The stock numbers are the denominator for every later comparison. Without them a
"2×" claim is unanchored.

---

## 6. Persistence testing (feeds `docs/09`)

After a passing S3 (gate 2 + gate 3):

| Step | Capture | Pass |
|---|---|---|
| FLR | S4 readout | readout still zero, SS0/SS1 unchanged |
| Driver rebind | S4 + gate 3 smoke (kernel 1 only) | per-clock gain retained |
| Sleep/wake | S2 readout | record whether it relocks (community reports say sleep can relock) |
| Full AC removal, 30 s, cold boot | S5 readout + gate 3 | readout zero **without** rerunning the unlock → true persistence |

Anything short of the last row is **automated replay**, not persistence. That
distinction is the whole point of `docs/09`.

---

## 7. Evidence record

One JSON per gate per condition, plus a transcript. Minimum fields:

```json
{
  "gate": 3,
  "condition": "unlocked",
  "date_utc": "…",
  "gpu": {"name": "…", "pci_id": "10DE:2684", "subsystem": "1462:5103",
          "vbios": "95.02.3C.40.B9", "driver": "…", "cuda": "…"},
  "run": {"shapes": [[4096,4096,4096]], "iters": 20, "warmup": 5,
          "clock_mhz_median": 2730, "power_w_median": 448, "temp_c_median": 71},
  "kernels": {"fp16_fp32acc": {"tflops": 0.0, "tflops_per_ghz": 0.0}},
  "verdict": "PASS|FAIL|INSUFFICIENT"
}
```

Keep raw per-iteration timings. Medians without raw data cannot be re-analysed
when a result looks wrong.

---

## 8. Harness status (what was actually tested)

`bench/tensor_gates.py` was executed in `--self-test` mode on this host:

| Test | Result |
|---|---|
| Gate 1 on a synthetic successful log | PASS |
| Gate 1 on an empty log | INSUFFICIENT |
| Gate 2 on the published **cold** capture | FAIL (correct: not unlocked) |
| Gate 3 on synthetic 2× signal + flat controls | PASS |
| Gate 3 on a selector-only result (no gain) | FAIL |
| Gate 3 with a missing required kernel | INSUFFICIENT |

The GPU path (`run` subcommand) was **not** executed: this host has no NVIDIA
GPU and `torch` is not installed. The code is written for `torch` ≥ 2.x with
CUDA; treat the first real run as the test of that path.
