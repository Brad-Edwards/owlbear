---
layout: default
title: ARM64 Hardware Checks
---

# ARM64 Hardware Checks

Hardware integrity checks that only a kernel module can perform. eBPF programs cannot access ARM64 system registers — this is the primary reason for the hybrid architecture.

## System Register Monitoring

At module init, baseline values are captured for:

| Register | What It Controls |
|----------|-----------------|
| `SCTLR_EL1` | MMU enable, caches, WXN (Write-implies-eXecute-Never) |
| `TCR_EL1` | Translation table configuration (page table format) |
| `MAIR_EL1` | Memory attribute indirection (cache policies) |
| `MDSCR_EL1` | Monitor debug system control (KDE, MDE, SS) |
| `VBAR_EL1` | Exception vector table base address |

A delayed workqueue re-reads these every 5 seconds and compares against baselines.

### What Tampering Looks Like

**WXN disabled** (SCTLR_EL1 bit 19 cleared): allows memory pages that are both writable AND executable. Normally the kernel enforces W^X — a page can be writable or executable, not both. Clearing WXN lets a cheat allocate RWX memory without mprotect tricks.

**VBAR_EL1 changed**: the exception vector table has been redirected. A cheat running at EL1 could replace the vector table to intercept all exceptions (syscalls, interrupts) and filter them through cheat code.

**MDSCR_EL1 KDE set**: kernel debug has been enabled after boot. This could indicate a debugger or cheat has configured hardware debug features from kernel mode.

**TCR/MAIR changed**: translation configuration has been modified. Could indicate an attack on page table layout or memory attribute policies.

## Debug Register Scanning

ARM64 provides up to 16 hardware breakpoints and 16 hardware watchpoints (vs 4 breakpoints on x86). These are set via `DBGBCR`/`DBGBVR` (breakpoints) and `DBGWCR`/`DBGWVR` (watchpoints).

Cheats use hardware breakpoints for stealthy function hooking: set a breakpoint on a game function, handle the debug exception in a custom handler, redirect execution to cheat code. No code modification required — invisible to code integrity checks.

Owlbear reads `DBGBCR0_EL1` through `DBGBCR5_EL1` and `DBGWCR0_EL1` through `DBGWCR3_EL1` via inline MRS instructions. The enable bit (bit 0) is checked. Any active register is reported with its target address.

Register indices must be compile-time constants for MRS — each register is read with a separate macro expansion, not a runtime loop.

## PAC Key Monitoring

On ARMv8.3+ with Pointer Authentication:

- CPU signs pointers using keys stored in `APIAKeyHi_EL1` / `APIAKeyLo_EL1`
- Signature occupies unused upper bits of 64-bit pointers
- `PACIA` / `AUTIA` instructions sign/verify

At init, owlbear captures the instruction A-key pair. Periodic checks detect:

1. **Key substitution**: a cheat replaces the key to forge valid signed pointers
2. **PAC disabled**: `SCTLR_EL1.EnIA` cleared, disabling authentication entirely

PAC checks are conditional on `CONFIG_ARM64_PTR_AUTH` and runtime feature detection via `system_supports_address_auth()`. On non-PAC hardware, these checks are no-ops.

## Why Periodic (Not Continuous)

Continuous register polling would consume CPU. The 5-second interval is a trade-off:
- Fast enough to detect persistent tampering (a cheat that modifies registers must keep them modified)
- Slow enough to have negligible performance impact
- A cheat could theoretically modify and restore between checks — but it would need to synchronize with the workqueue timer, which runs on an unpredictable CPU
