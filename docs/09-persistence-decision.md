# Persistence decision

**Question:** which approach can make the RTX 4090 tensor-rate change permanent,
and which only *look* permanent?

The project has to be precise about four different things that are often all
called "persistent":

| Class | Definition | Survives |
|---|---|---|
| **A. On-card default** | the card's own reset default is changed | power loss, new host, no software |
| **B. Portable reapply** | a component that travels with the card or host firmware reapplies it before any driver | power loss, same host (or same card in another host) |
| **C. Host-dependent automatic** | host firmware/boot entry reapplies it on every boot | power loss, same host, requires that boot path |
| **D. Runtime** | software applies it after the OS starts | until the next reset/power cycle |

Only **A** is what a buyer would call "unlocked". Everything else is automation.

---

## 1. Decision table

| Approach | Verdict | Class if it worked | Reason |
|---|---|---|---|
| **Modified VBIOS table** | **NO-GO** | A | No authenticated, writable field that seeds the rate exists in the examined image. The VBIOS tables are covered by the ROM signature; the profile delta contains power/thermal/provisioning records only; no plaintext region references `0x8238xx`. There is nothing to edit that would change the default, and editing signed tables breaks the image. |
| **Modified signed firmware (FWSEC/Booter/GSP)** | **NO-GO** | A | FWSEC IMEM is AES ciphertext (entropy 7.996, 0 % zeros) and the descriptor carries two RSA-3K signatures with version mask `0x3`. Any modification invalidates SEC2 authentication. No plaintext copy exists to patch, and no evidence says this firmware even writes the rate. |
| **Fuse/strap origin** | **INSUFFICIENT EVIDENCE** (leading explanation) | n/a — not a lever | Best-supported explanation of the default (see `docs/06`), but OTP fuses are one-time and the project will not program them. This decides *what persistence is possible*, not how to get it. The cross-SKU read in `docs/06` §7 is the test. |
| **Automatic UEFI unlock (option-ROM application / boot entry)** | **GO** | C | Demonstrated by three independent public projects, including one verified on a 4090. Volatile by construction: it must run every boot, before the driver. Recoverable (no flash), reviewable (source available), and does not touch Secure Boot or the card. |
| **Motherboard DXE integration** | **NO-GO** | B | Same effect as C with a much worse failure domain: Boot Guard, firmware rollback, ME interactions, and a non-booting motherboard on error. The mission's own criterion — "is the added risk justified over ordinary UEFI boot automation?" — is answered no. |
| **GPU option-ROM companion driver** | **INSUFFICIENT EVIDENCE** | B (the only true "portable" route) | The idea is sound: a UEFI driver in the GPU's own option ROM would run at POST on any host. But the EFI image is signed (Microsoft UEFI CA 2011), the ROM is signature-covered, and adding an unsigned driver would be refused under Secure Boot. No public project has done it; the OVMF experiment in §4 is the cheapest way to find out whether image discovery and dispatch are even possible before investing further. |

---

## 2. Why the two "modify the card" routes are closed

| Requirement for a persistent on-card default | Status |
|---|---|
| A writable field that the hardware reads as the rate default | **Not found.** No plaintext region references any `FEAT_OVR_SM_SPD`/`FUSE_SS_*` word; the only `0x0082xxxx` access is a memory-partition read. |
| A way to write that field without breaking authentication | **None.** The ROM image, the EFI image and the FWSEC are each signed; the FWSEC is also encrypted. |
| A fuse-programming path | **Out of scope and one-time.** OTP; not authorised, not reversible. |
| Evidence that firmware sets the rate at boot | **None.** No plaintext firmware writes `0x8238xx`; the encrypted FWSEC's side effects are unobservable. |

That is why the previous absolute claim ("the VBIOS cannot affect the
restriction") is replaced by the narrower, defensible one: *no examined region
contains such a mechanism, and none is expected in the encrypted region, but the
encrypted region cannot be inspected.*

---

## 3. The GO route, stated precisely

**Host-dependent automatic UEFI unlock** is the only approach with working
public evidence:

| Project | Mechanism | Evidence level |
|---|---|---|
| `MarvinFS/rtx4090-uefi` | UEFI application re-applies the transaction before Windows on every boot | verified on one MSI 4090 / ASRock X870E host; sleep relocks |
| `Windows-GPU-UNLOCK` | profile-gated UEFI boot application | experimental, one profile |
| `physicsdolphin/nv-uefi-unlocker` | cross-platform UEFI loader, protected-register readbacks | source + FAQ + DXE feasibility study |
| `PantACRO4life/gpu-unlock-4090-windows` | exact MSI Suprim X + Z790 GODLIKE port | one exact configuration |

Operational consequences, all of which belong in any claim:

1. **It is per-boot.** Every cold boot, resume from hibernate, and usually
   sleep/wake needs the transaction again. That is class C, not A.
2. **It is host-dependent.** The boot entry lives on one machine. Move the card
   to another PC and it is stock.
3. **It is driver-version sensitive.** The pinned firmware is 610.43.03; a
   different driver generation can change the transaction's assumptions.
4. **It requires Secure Boot to be off or the application to be trusted.** That
   is a host security change with its own consequences (BitLocker recovery,
   attestation).
5. **It is recoverable.** No flash, no fuse, no firmware write. A bad run should
   leave the card usable after a power cycle, which is exactly why it is
   preferable to any on-card modification.

The simplest practical version is a single UEFI application on a dedicated USB
stick, launched manually at boot (one keypress), not an installed boot entry.
That is the lowest-risk way to get class C behaviour and it is trivially
reversible.

---

## 4. The one unproven idea worth an experiment (not a flash)

**Question:** can a UEFI driver image inside the GPU option ROM be discovered
and dispatched by firmware, so the unlock reapplies on any host?

**Test it only in OVMF, with a synthetic ROM** — never on the real GPU:

1. Build an OVMF firmware volume with a synthetic option ROM containing a
   code-type `0x03` EFI image that only prints a marker (no PCI access).
2. Attach it as a virtio/PCI device option ROM in QEMU; boot OVMF; check whether
   the driver is dispatched before `BootManager`.
3. Repeat with Secure Boot enabled in OVMF and an unsigned image: confirm the
   refusal.
4. Only if (2) succeeds and (3) shows a workable path (own key enrolled, or a
   signed image) does the idea merit a second look.

The mission's constraint stands: **synthetic firmware images only, in OVMF.
Never the real GPU as a firmware test target.**

---

## 5. What would change these verdicts

| If this were shown | Then |
|---|---|
| A professional AD102 reads `FUSE_SS_FMLA32 = 0` while the 4090 reads `1` | Fuse origin confirmed; on-card persistence is definitively closed and the GO route is the only option |
| A professional AD102 reads the same fuses as the 4090 but still runs full rate | Fuse origin refuted; authenticated firmware or a strap sets the rate, and the firmware track reopens (with SEC2 as the wall) |
| The VBIOS profile switch changes any `0x8238xx` readout at S0 | The VBIOS *does* seed part of the state; the NO-GO on modified tables must be revisited |
| A signed, vendor-supplied mechanism to set the rate were found | everything changes; none is known |
| OVMF dispatches a synthetic option-ROM driver **and** a signing path exists | the portable (class B) route becomes worth prototyping on a sacrificial card |

---

## 6. Recommendation

1. **Pursue the GO route** (host-dependent UEFI application, manual launch from
   a dedicated stick) as the practical automatic unlock. It is the only
   demonstrated path and the only one that is fully reversible.
2. **Do not touch** the VBIOS, the fuses, the signed firmware, the motherboard
   firmware, or Secure Boot for this purpose.
3. **Run the cross-SKU fuse read** (`docs/06` §7) before spending more effort on
   persistence. It is a read-only measurement and it decides whether any on-card
   route could ever exist.
4. Treat the option-ROM driver idea as a **research question for OVMF only**,
   with no hardware commitment until it passes §4.

**Strongest remaining persistence hypothesis:** the rate is a fuse-programmed
per-SKU default, therefore no on-card, host-independent unlock exists that does
not involve programming OTP or breaking SEC2. Under that hypothesis, class C
(automatic pre-OS replay) is not a compromise — it is the ceiling.

**Simplest practical automatic unlock:** a single reviewed UEFI application on a
USB stick, launched at boot, that runs the existing transaction and verifies it
with the gate-2 readback before handing off to Windows.
