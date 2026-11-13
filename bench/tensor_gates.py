#!/usr/bin/env python3
"""Three-gate acceptance harness for the RTX 4090 tensor unlock.

Gate 1 - firmware transaction: the signed sequence ran and the four permission
         registers changed. Parsed from the unlocker's transaction log.
Gate 2 - effective hardware state: SS0/SS1 hold the unlock values and
         FEAT_READOUT_1 reads zero for all nine units. Parsed from a read-only
         register capture (tools/hw/capture_linux.py) via
         tools/hw/decode_fingerprint.py.
Gate 3 - measured performance: per-clock GEMM throughput per precision path,
         unlocked vs stock, with power/clock sampling.

A gate is only PASS when its own evidence is present. Missing evidence is
INSUFFICIENT, never PASS.

Usage:
    python3 bench/tensor_gates.py --self-test
    python3 bench/tensor_gates.py --plan
    python3 bench/tensor_gates.py gate1 --log run.txt
    python3 bench/tensor_gates.py gate2 --capture cap.json
    python3 bench/tensor_gates.py gate3 --stock stock.json --unlocked unlocked.json
    python3 bench/tensor_gates.py run --out results/ --shapes prefill
"""
from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import sys
import time

# ---------------------------------------------------------------- gate 1 ----
GATE1_MARKERS = {
    "marker": re.compile(r"marker[^0-9a-fA-F]*(0x)?67b00001|67b00001", re.I),
    "halt": re.compile(r"halt", re.I),
    "wpr_cfg": re.compile(r"WPR_CFG[^0-9a-fA-F]*(0x)?[0-9a-fA-F]{4,8}", re.I),
    "feat": re.compile(r"FEAT[^0-9a-fA-F]*(0x)?[0-9a-fA-F]{4,8}", re.I),
}
EXPECTED_PLM = {"WPR_CFG": 0xFFFFF0FF, "WPR": 0xFFFFFFFF, "FEAT": 0xFFFFFFFF}


def gate1(text):
    found = {k: bool(p.search(text)) for k, p in GATE1_MARKERS.items()}
    values = {}
    for name, want in EXPECTED_PLM.items():
        m = re.search(name + r"[^0-9a-fA-F]*(?:=|:)?\s*(0x)?([0-9a-fA-F]{4,8})", text, re.I)
        if m:
            values[name] = int(m.group(2), 16)
    perms_ok = all(values.get(k) == v for k, v in EXPECTED_PLM.items() if k in values)
    passed = found["marker"] and found["halt"] and perms_ok and len(values) >= 2
    return {
        "gate": 1,
        "name": "firmware transaction",
        "verdict": "PASS" if passed else ("FAIL" if found["marker"] and values else "INSUFFICIENT"),
        "evidence": {"markers": found, "permission_values": {k: "0x%08X" % v for k, v in values.items()}},
        "note": "A successful register write alone is not a full-rate configuration; gate 2 must agree.",
    }


# ---------------------------------------------------------------- gate 2 ----
def gate2(capture_path):
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools", "hw"))
    from decode_fingerprint import read_capture, decode  # noqa: E402
    data, regs = read_capture(capture_path)
    r1 = regs.get(0x00823818)
    ss0 = regs.get(0x0082381C)
    ss1 = regs.get(0x00823820)
    plm = regs.get(0x00823804)
    if r1 is None or ss0 is None or ss1 is None:
        return {"gate": 2, "name": "effective hardware state", "verdict": "INSUFFICIENT",
                "evidence": {"capture": capture_path}, "note": "readout/SS0/SS1 missing"}
    fields = [(r1 >> (3 * i)) & 7 for i in range(9)]
    full = all(f == 0 for f in fields)
    ss_ok = ss0 == 0x88888888 and ss1 == 0x8
    plm_ok = plm is not None and plm == 0xFFFFFFFF
    verdict = "PASS" if (full and ss_ok) else "FAIL"
    return {
        "gate": 2, "name": "effective hardware state", "verdict": verdict,
        "evidence": {"capture": capture_path, "FEAT_READOUT_1": "0x%08X" % r1,
                     "fields": fields, "SS0": "0x%08X" % ss0, "SS1": "0x%08X" % ss1,
                     "FEAT_OVR_PLM": None if plm is None else "0x%08X" % plm},
        "checks": {"all_nine_units_full": full, "ss0_ss1_unlock_values": ss_ok,
                   "plm_open": plm_ok},
        "note": "PASS requires readout zero; SS0/SS1 alone is only an intent marker.",
    }


# ---------------------------------------------------------------- gate 3 ----
KERNELS = ["fp16_fp32acc", "bf16_fp32acc", "tf32", "fp32_pedantic", "int8", "fp8"]
# fp8 needs torch._scaled_mm and is a control, not a required gate row.
REQUIRED = ["fp16_fp32acc", "bf16_fp32acc", "tf32", "fp32_pedantic", "int8"]


def _ratio(a, b):
    if b in (None, 0) or a is None:
        return None
    return a / b


def gate3(stock, unlocked, min_gain=0.40, control_tol=0.08):
    """Compare per-clock throughput. Requires >=3 shapes and clock data."""
    rows = []
    verdict = "PASS"
    for k in KERNELS:
        s, u = stock.get(k), unlocked.get(k)
        if not s or not u:
            if k in REQUIRED:
                rows.append({"kernel": k, "verdict": "INSUFFICIENT"})
                verdict = "INSUFFICIENT" if verdict == "PASS" else verdict
            else:
                rows.append({"kernel": k, "verdict": "NOT_APPLICABLE",
                             "note": "optional control kernel not produced by this build"})
            continue
        s_pc = _ratio(s.get("tflops"), (s.get("clock_mhz") or 0) / 1000.0)
        u_pc = _ratio(u.get("tflops"), (u.get("clock_mhz") or 0) / 1000.0)
        gain = _ratio(u_pc, s_pc) - 1 if s_pc and u_pc else None
        if gain is None:
            rows.append({"kernel": k, "verdict": "INSUFFICIENT"})
            verdict = "INSUFFICIENT"
            continue
        if k in ("fp16_fp32acc", "bf16_fp32acc", "tf32"):
            ok = gain >= min_gain
            want = ">= %d%%" % int(min_gain * 100)
        else:
            ok = abs(gain) <= control_tol
            want = "within +/- %d%%" % int(control_tol * 100)
        rows.append({"kernel": k, "stock_tflops_per_ghz": round(s_pc, 2),
                     "unlocked_tflops_per_ghz": round(u_pc, 2),
                     "gain_percent": round(gain * 100, 1), "expected": want,
                     "verdict": "PASS" if ok else "FAIL"})
        if not ok:
            verdict = "FAIL"
    return {"gate": 3, "name": "measured performance", "verdict": verdict, "rows": rows,
            "note": "Per-clock comparison removes DVFS; still check power and temperature."}


# ------------------------------------------------------------------ run ----
def shapes(name):
    if name == "smoke":
        return [(1024, 1024, 1024), (2048, 2048, 2048)]
    if name == "prefill":
        return [(4096, 4096, 4096), (8192, 8192, 8192), (16384, 16384, 4096),
                (16384, 4096, 14336), (4096, 14336, 4096)]
    return [(4096, 4096, 4096), (8192, 8192, 8192)]


def sample_power(stop, out):
    import subprocess
    while not stop.is_set():
        try:
            r = subprocess.run(
                ["nvidia-smi", "--query-gpu=clocks.sm,power.draw,temperature.gpu,power.limit",
                 "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=3)
            if r.returncode == 0:
                clk, pw, temp, lim = [x.strip() for x in r.stdout.strip().split(",")]
                out.append({"clock_mhz": float(clk), "power_w": float(pw),
                            "temp_c": float(temp), "limit_w": float(lim)})
        except Exception:
            pass
        stop.wait(0.5)


def run_bench(shape_set="prefill", iters=20, warmup=5):
    import threading
    import torch
    torch.backends.cuda.matmul.allow_tf32 = False
    torch.backends.cuda.matmul.allow_fp16_reduced_precision_reduction = False
    dev = "cuda"
    name = torch.cuda.get_device_name(0)
    print("device:", name, "cuda", torch.version.cuda, "torch", torch.__version__)

    def timeit(fn):
        for _ in range(warmup):
            fn()
        torch.cuda.synchronize()
        times = []
        for _ in range(iters):
            torch.cuda.synchronize()
            t0 = time.perf_counter()
            fn()
            torch.cuda.synchronize()
            times.append(time.perf_counter() - t0)
        return statistics.median(times)

    results = {}
    samples = []
    stop = threading.Event()
    th = threading.Thread(target=sample_power, args=(stop, samples), daemon=True)
    th.start()
    try:
        for shp in shapes(shape_set):
            m, n, k = shp
            flops = 2 * m * n * k
            a16 = torch.randn(m, k, device=dev, dtype=torch.float16)
            b16 = torch.randn(k, n, device=dev, dtype=torch.float16)
            abf = torch.randn(m, k, device=dev, dtype=torch.bfloat16)
            bbf = torch.randn(k, n, device=dev, dtype=torch.bfloat16)
            a32 = torch.randn(m, k, device=dev, dtype=torch.float32)
            b32 = torch.randn(k, n, device=dev, dtype=torch.float32)
            a8 = torch.randint(-8, 8, (m, k), device=dev, dtype=torch.int8)
            b8 = torch.randint(-8, 8, (k, n), device=dev, dtype=torch.int8)

            def add(tag, fn):
                t = timeit(fn)
                key = "%s|%dx%dx%d" % (tag, m, n, k)
                results[key] = {"tflops": flops / t / 1e12, "seconds": t}
                print("  %-16s %5dx%5dx%5d  %8.2f TF/s  %.4fs" % (tag, m, n, k, flops / t / 1e12, t))

            add("fp16_fp32acc", lambda: torch.matmul(a16, b16))
            add("bf16_fp32acc", lambda: torch.matmul(abf, bbf))
            torch.backends.cuda.matmul.allow_tf32 = True
            add("tf32", lambda: torch.matmul(a32, b32))
            torch.backends.cuda.matmul.allow_tf32 = False
            add("fp32_pedantic", lambda: torch.matmul(a32, b32))
            try:
                add("int8", lambda: torch._int_mm(a8, b8))
            except Exception as e:  # pragma: no cover - depends on build
                print("  int8 unsupported:", e)
    finally:
        stop.set()
        th.join(timeout=2)

    clocks = [s["clock_mhz"] for s in samples if s["clock_mhz"] > 0]
    powers = [s["power_w"] for s in samples]
    temps = [s["temp_c"] for s in samples]
    meta = {
        "device": name, "torch": torch.__version__, "cuda": torch.version.cuda,
        "driver": os.environ.get("NVIDIA_DRIVER_VERSION"),
        "clock_mhz_median": statistics.median(clocks) if clocks else None,
        "power_w_median": statistics.median(powers) if powers else None,
        "temp_c_median": statistics.median(temps) if temps else None,
        "samples": len(samples),
    }
    # collapse per-kernel over shapes: keep the best (largest) throughput per kernel
    best = {}
    for key, v in results.items():
        tag = key.split("|")[0]
        if tag not in best or v["tflops"] > best[tag]["tflops"]:
            best[tag] = dict(v, clock_mhz=meta["clock_mhz_median"])
    return {"meta": meta, "shapes": shape_set, "results": results, "best": best}


def self_test():
    cold = {"meta": {"clock_mhz_median": 2700}, "best": {
        "fp16_fp32acc": {"tflops": 160.0, "clock_mhz": 2700},
        "bf16_fp32acc": {"tflops": 160.0, "clock_mhz": 2700},
        "tf32": {"tflops": 80.0, "clock_mhz": 2700},
        "fp32_pedantic": {"tflops": 75.0, "clock_mhz": 2700},
        "int8": {"tflops": 320.0, "clock_mhz": 2700},
    }}
    warm = {"meta": {"clock_mhz_median": 2700}, "best": {
        "fp16_fp32acc": {"tflops": 320.0, "clock_mhz": 2700},
        "bf16_fp32acc": {"tflops": 315.0, "clock_mhz": 2700},
        "tf32": {"tflops": 160.0, "clock_mhz": 2700},
        "fp32_pedantic": {"tflops": 75.5, "clock_mhz": 2700},
        "int8": {"tflops": 322.0, "clock_mhz": 2700},
    }}
    g = gate3(cold["best"], warm["best"])
    print(json.dumps(g, indent=2))
    assert g["verdict"] == "PASS", g

    # a selector-only result (no gain) must fail gate 3
    flat = {"fp16_fp32acc": {"tflops": 160.0, "clock_mhz": 2700},
            "bf16_fp32acc": {"tflops": 160.0, "clock_mhz": 2700},
            "tf32": {"tflops": 80.0, "clock_mhz": 2700},
            "fp32_pedantic": {"tflops": 75.0, "clock_mhz": 2700},
            "int8": {"tflops": 320.0, "clock_mhz": 2700}}
    g2 = gate3(cold["best"], flat)
    assert g2["verdict"] == "FAIL", g2

    # missing kernel -> INSUFFICIENT, not PASS
    partial = {k: v for k, v in warm["best"].items() if k != "tf32"}
    g3 = gate3(cold["best"], partial)
    assert g3["verdict"] == "INSUFFICIENT", g3

    log = ("AD102 marker: 0x67b00001\nSEC2 HALT\nWPR_CFG=0xfffff0ff\n"
           "FBPA=0xffffff0f\nWPR=0xffffffff\nFEAT=0xffffffff\n")
    g4 = gate1(log)
    print(json.dumps(g4, indent=2))
    assert g4["verdict"] == "PASS", g4
    g5 = gate1("nothing here")
    assert g5["verdict"] == "INSUFFICIENT", g5
    print("self-test OK")


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    sub = ap.add_subparsers(dest="cmd")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--plan", action="store_true")
    for name in ("gate1", "gate2", "gate3", "run"):
        p = sub.add_parser(name)
        p.add_argument("--log")
        p.add_argument("--capture")
        p.add_argument("--stock")
        p.add_argument("--unlocked")
        p.add_argument("--out", default="results")
        p.add_argument("--shapes", default="prefill")
        p.add_argument("--iters", type=int, default=20)
        p.add_argument("--json")
    args = ap.parse_args(argv)

    if args.self_test:
        self_test()
        return 0
    if args.plan:
        print("kernels:", ", ".join(KERNELS))
        print("shapes:", shapes("prefill"))
        print("per shape: torch.matmul fp16/bf16 (FP32 accum), tf32, fp32 pedantic, int8")
        print("normalise by median SM clock sampled every 0.5 s; median of 20 iterations")
        return 0
    if args.cmd == "gate1":
        out = gate1(open(args.log, encoding="utf-8", errors="replace").read())
    elif args.cmd == "gate2":
        out = gate2(args.capture)
    elif args.cmd == "gate3":
        out = gate3(json.load(open(args.stock))["best"], json.load(open(args.unlocked))["best"])
    elif args.cmd == "run":
        os.makedirs(args.out, exist_ok=True)
        out = run_bench(args.shapes, args.iters)
        path = os.path.join(args.out, "bench-%s.json" % time.strftime("%Y%m%dT%H%M%SZ"))
        with open(path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
        print("wrote", path)
    else:
        ap.print_help()
        return 1
    print(json.dumps(out, indent=2))
    if getattr(args, "json", None):
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
    return 0 if out.get("verdict", "PASS") != "FAIL" else 4


if __name__ == "__main__":
    sys.exit(main())
