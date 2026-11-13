# Public field data: what other people have already measured

**Purpose.** `docs/06` proposed a cross-SKU register read as "the one experiment
that settles it". It turns out most of that experiment has already been run in
public, on two generations. This document collects the measurements, says what
each one establishes, and marks what is still missing.

All entries are **OBSERVED (third-party)** — reported by named people with
methods and, in most cases, raw logs. None were reproduced on our hardware.
Where a claim depends on them, `docs/06` says so.

---

## 1. Ampere, 15 cards: the professional/consumer fuse split is measured

Source: *GA100 Fuse & Register Reference Table*, gist `JRex286/0480d2b2…`,
probed with a read-only script (`tools/mmio-probe/probe.sh`) across **2× CMP
170HX**, **11 rented Ampere cards**, and **2× Drive A100 32 GB** (physical).

| Register | CMP 170HX | A100 40G | A100 80G | A10 | A5000 | **A6000** | RTX 3080 | RTX 3080 Ti | RTX 3090 | RTX 3090 Ti |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `FUSE_SS_FMLA32` `0x8207D8` | 5 | 0 | 0 | 0 | 0 | **0** | 1 | 1 | 1 | 1 |
| `FUSE_SS_IMLA4` `0x8207EC` | 5 | 0 | 0 | 0 | 0 | **0** | 1 | 1 | 1 | 1 |
| `FEAT_READOUT_1` `0x823818` | `016db6ed` | 0 | 0 | 0 | 0 | **0** | `00400080` | `00400080` | `00400080` | `00400080` |
| `FEAT_OVR_PLM` `0x823804` | `ffffff8f` | `ffffff8f` | `ffffff8f` | `ffffff8f` | `ffffff8f` | `ffffff8f` | `ffffff8f` | `ffffff8f` | `ffffff8f` | `ffffff8f` |

The gist's own summary: *"Speed select (FMLA32 + IMLA4): `0x1` on ALL consumer
GeForce, `0x0` on ALL professional/datacenter, `0x5` on CMP."* Six professional
parts, nine consumer parts, one CMP part, no exceptions.

**What it establishes:** on Ampere, the professional card's full rate is
associated with **fuse value 0** and the consumer's half rate with **fuse value
1**, measured on physical hardware at the same register addresses we use. The
fuse and the rate move together across a 15-card sample.

**What it does not establish:** anything about Ada. Different die, different
fuse map in principle (though the addresses are unchanged).

---

## 2. Ada consumer, cold, no driver: the state exists before GSP-RM

Source: `Zagitta/gpu-unlock` issue #4, comment by `mongoled` (2026-10-23).
Method: out-of-tree read-only probe module, cold boot with
`module_blacklist=nvidia,nvidia_drm,nvidia_modeset,nvidia_uvm`,
`driver=<none>`, `state=0`. Three RTX 4060 Ti (`10de:2803`).

| Register | Card A / B / C |
|---|---|
| `FEAT_OVR_PLM` `0x823804` | `ffffff8f` on all three |
| `FEAT_READOUT_1` `0x823818` | **`00410080` on all three** |
| `SS0` `0x82381C` | `04022036` / `17150016` / `15324120` — no nibble ≥ 8 |
| `FUSE_SS_FMLA32` / `IMLA2` / `IMLA4` | `1` / `1` / `1` on all three |
| `FUSE_FEAT_OVR_DIS` `0x8203F0` | `0` (master kill fuse unblown) |

A fourth Ada card — RTX 4070 Ti Super (`10de:2705`, AD103) — was probed cold by
`CannaraX` with the same module and reported the same block.

**What it establishes:** the reduced readout (`0x00410080`, three fields at 2)
is present on a **cold Ada card with no driver bound**. GSP-RM is loaded by the
host driver; it was not running. So the default state is not host software.

---

## 3. Ada consumer, three RTX 4090s: the same three fuses, on our card family

Source: same issue, comment by `axAilotl` (2026-10-23), read-only probe, live
with the driver bound (BAR0 mmap).

| Card | VBIOS | `FUSE_SS_FMLA32/IMLA2/IMLA4` | `FEAT_READOUT_1` | `SS0` |
|---|---|---|---|---|
| 4090 #1 | `95.02.18.80.E9` | 1 / 1 / 1 | `00410080` | `33022044` |
| 4090 #2 | **`95.02.3C.40.B7`** | 1 / 1 / 1 | `00410080` | `34124107` |
| 4090 #3 | `95.02.3C.00.60` | 1 / 1 / 1 | `00410080` | `47700162` |

Card #2's VBIOS `95.02.3C.40.B7` is the **same 95.02.3C.40 family** as our
`B9` (performance) and `B8` (silent), on a different board. Three boards, two
VBIOS families, two driver branches, identical fuse tier and readout.

**What it establishes:** our card's expected values are not special, and the
`0x00410080` pattern is the Ada consumer norm. The reads are post-driver, so
they show the driver does not change the state — not what it is pre-driver
(that is §2's job, on AD106).

---

## 4. The RM getter names the three fields

Source: same issue, comment by `sztlink` (2026-10-25), RTX 4090 / Ubuntu 24.04
/ driver 595.91.07.

> "The official RM getter reported FMLA32/IMLA2/IMLA4 **1/1/1 stock -> 0/0/0
> unlocked**, including after driver initialization and workloads. A later cold
> stock boot restored 1/1/1."

**What it establishes:** NVIDIA's own driver-side fuse getter names exactly the
three fields our readout decode singled out (`docs/06` §2.3), and they are the
ones that flip. That mapping was **INFERRED** in `docs/06`; this makes it
**OBSERVED** — the names come from the vendor driver, not from our arithmetic.

---

## 5. Counter-evidence and corrections these reports force

| Report | Consequence for our documents |
|---|---|
| `FECS_FEAT_OVERRIDE` / `FECS_FEAT_READOUT_1` (`0x409664` / `0x409668`) read **`0xbadf5040`** on every Ampere part probed | **Corrects `docs/08`.** That block is inaccessible; it must not be used as a gate-2 cross-check. Removed. |
| `SM_ISSUE_RATE_MODIFIER` (`0x504204`) = `0x5` on A100 **and** 170HX, "host-writable but no perf change when zeroed" | It is not the throttle register. `docs/07` lists it as context only; keep it that way. |
| `mongoled`: on Ada, `SS0`/`SS1` **reject PL0 writes** while the gate is closed | Consistent with our model (the payload must open `FEAT_OVR_PLM` first), and it means a "just write the selectors" shortcut does not exist on Ada. |
| `mongoled`: prod and debug FWSEC code regions differ in 99.59 % of bytes but share 22 repeated ciphertext blocks at identical offsets | Supports "same plaintext, different AES key" for the debug/production pair — which is what made our `0x45`/`0x85` reading safe. |
| `sztlink`: cold vs initialized 1 MiB PROM views differed **only in a 128 KiB tail**; chain/descriptor/FWSEC stayed equal | Our dumps are the same ROM either way for the parts that matter. Useful when comparing captures. |

---

## 6. What is still missing

| Cell | Status |
|---|---|
| **Ada professional fuse tier** (RTX 6000 Ada, L40, RTX 5000 Ada) | **Not found anywhere public.** No dump, no probe report, no vendor document. |
| Ada `FEAT_READOUT_1` on a professional part | Not found |
| A cold (pre-driver) read on an **RTX 4090** specifically | The AD106 cold read covers Ada consumer; our exact board has only post-driver reads |

Given §1 (six professional Ampere parts at fuse 0, nine consumer at 1), §2 (Ada
consumer half-rate pre-driver), and §4 (the vendor's own getter names the same
three fields), the Ada-professional cell is now a **confirmation, not a
discovery**. A missing confirmation is worth one paragraph in `docs/06`, not a
hardware programme.

---

## 7. What this means for the project

The mission asked whether a professional AD102's higher throughput comes from
hardware fuses or authenticated firmware. The evidence now reads:

1. **ROM firmware:** excluded by our own bit-identical comparison (`docs/05`
   §3.5) — one FWSEC binary, 33 DMEM bytes of per-SKU parameter.
2. **Host software:** excluded by the cold AD106 reads (§2) — no driver, same
   reduced readout.
3. **Fuse/strap:** directly measured as the discriminator on 15 Ampere cards
   (§1), with the vendor's own getter naming the same three fields on Ada (§4).

What remains is "which piece of hardware reads the fuse" — OTP, a strap, or the
GPU's boot ROM — and that is not answerable from outside the chip. It is also
not actionable: none of the three can be changed by the project.

**So the honest status of the critical question is: answered to the limit of
what static analysis and public field data can answer, with one confirming
measurement outstanding on Ada professional silicon.**
