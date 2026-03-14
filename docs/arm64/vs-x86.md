---
layout: default
title: ARM64 vs x86 for Anti-Cheat
---

# ARM64 vs x86 for Anti-Cheat

Key architectural differences that affect anti-cheat design.

## Privilege Model

| | x86_64 | ARM64 |
|---|---|---|
| Levels | Ring 0-3 + SMM | EL0-EL3 + Secure World |
| Kernel | Ring 0 | EL1 |
| Hypervisor | Ring -1 (VT-x/AMD-V, bolted on) | EL2 (clean, first-class) |
| Trusted execution | SGX (deprecated), TDX | TrustZone (EL3 + Secure World) |
| Syscall entry | `SYSCALL` via `IA32_LSTAR` MSR | `SVC` instruction, `VBAR_EL1` vector |

ARM64's EL model is cleaner — no legacy Ring 1/2 baggage, no SMM. TrustZone provides hardware isolation that SGX only approximated.

## Memory Architecture

| | x86_64 | ARM64 |
|---|---|---|
| Page table base | Single `CR3` | Split `TTBR0_EL1` (user) / `TTBR1_EL1` (kernel) |
| I/D cache coherency | Coherent (hardware snoop) | Non-coherent (explicit `IC IVAU` + `ISB` needed) |
| Page granules | 4KB only | 4KB, 16KB, or 64KB |
| Execute permission | NX bit (single) | UXN + PXN (separate user/kernel execute control) |
| W^X enforcement | Software (OS enforced) | Hardware `WXN` bit in `SCTLR_EL1` |

### I/D Cache Non-Coherency

This is significant for anti-cheat. On x86, writing code to memory and jumping to it works immediately — the instruction cache sees the write via hardware snooping. On ARM64, you must explicitly flush the instruction cache (`DC CVAU` + `DSB ISH` + `IC IVAU` + `DSB ISH` + `ISB`).

A cheat injecting code into a game process on ARM64 must execute these cache maintenance instructions. Under a hypervisor, these can be trapped (HCR_EL2 TPC/TPU bits), making code injection detectable at the hardware level.

## Debug Capabilities

| | x86_64 | ARM64 |
|---|---|---|
| HW breakpoints | 4 (DR0-DR3) | Up to 16 (DBGBVR0-15) |
| HW watchpoints | 4 (shared with BPs) | Up to 16 (DBGWVR0-15, separate) |
| Debug control | DR7 | DBGBCR/DBGWCR per register |
| Kernel debug | Per-thread via DR7 | MDSCR_EL1.KDE global |

ARM64 has 4x more hardware breakpoints and separate watchpoint registers. More to monitor, but also more powerful for the cheat developer.

## Kernel Patch Protection

| | x86_64 (Windows) | ARM64 (Linux) |
|---|---|---|
| Protection | PatchGuard monitors SSDT, IDT, GDT, MSRs, kernel code | None built-in |
| Effect | BSOD on modification | No enforcement |
| Implication | ACs and cheats use documented callbacks, not direct hooks | Cheats can hook anything — but so can the AC |

Linux has no PatchGuard equivalent. This means cheats have more freedom (direct syscall table hooks, vector table replacement) but the anti-cheat also has more freedom. The playing field is symmetric.

## Anti-Cheat Implications

**ARM64 advantages:**
- PAC makes ROP/JOP and function pointer hijacking harder
- WXN is hardware-enforced W^X — clearing it is detectable (owlbear monitors this)
- Non-coherent I-cache makes code injection detectable at the hypervisor level
- TrustZone can host tamper-proof integrity checks (out of scope for prototype)
- More debug registers = more monitoring surface for cheat detection

**ARM64 challenges:**
- Smaller gaming ecosystem = less battle-tested anti-cheat code
- No PatchGuard = cheats can hook kernel freely
- Memory ordering is weaker = must use explicit barriers in concurrent code (easy to get wrong)
- Tooling maturity lags x86 (debuggers, RE tools, kernel debugging)
