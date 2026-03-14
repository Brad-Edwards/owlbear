---
layout: default
title: PAC, MTE, BTI
---

# ARM64 Security Features for Anti-Cheat

ARM64 provides hardware security features with no x86 equivalent. These change what's possible for both cheats and anti-cheat.

## PAC — Pointer Authentication (ARMv8.3+)

**What it does:** signs pointers using a key + context. The signature occupies unused upper bits of 64-bit pointers. Verification happens on use — a forged or corrupted pointer causes a fault.

**Keys:** five key pairs (IA, IB, DA, DB, GA) stored in system registers. IA signs instruction pointers (return addresses, function pointers). DA signs data pointers.

**Anti-cheat use:**
- Return addresses on the stack are signed. ROP chains cannot work without the key.
- Function pointers in game structs can be signed. Vtable hijacking requires key knowledge.
- Owlbear captures `APIAKeyHi/Lo_EL1` at init and detects substitution.
- If `SCTLR_EL1.EnIA` is cleared, PAC is disabled entirely — owlbear detects this.

**Cheat implications:** a cheat cannot forge valid signed pointers without the per-process key. Key extraction requires kernel access. Key substitution is detectable.

**Hardware:** Graviton3 (c7g instances) supports PAC. Graviton2 (t4g, m6g) does not.

## MTE — Memory Tagging Extension (ARMv8.5+)

**What it does:** associates a 4-bit tag with every 16-byte memory granule. Pointers carry a tag in bits [59:56]. On access, the pointer tag is compared against the memory tag. Mismatch = fault.

**Anti-cheat use (theoretical):**
- Tag critical game data structures. A cheat reading memory with the wrong tag causes a fault.
- Detect use-after-free and buffer overflow in game code (same mechanism as ASAN but in hardware).
- Tag anti-cheat's own data to detect tampering.

**Status in owlbear:** documented only. MTE requires ARMv8.5+ hardware. No current Graviton instance supports MTE. Apple M-series supports it but macOS doesn't expose it to third-party code.

## BTI — Branch Target Identification (ARMv8.5+)

**What it does:** marks valid indirect branch targets with a `BTI` instruction. If an indirect branch (BR, BLR) lands on a non-BTI instruction, a fault occurs.

**Anti-cheat use:**
- Prevents JOP (Jump-Oriented Programming) — the ARM64 equivalent of ROP using indirect jumps instead of returns.
- A cheat cannot redirect indirect branches to arbitrary code locations.
- Complements PAC: PAC protects return addresses, BTI protects indirect call/jump targets.

**Cheat implications:** code injection via indirect branch redirection requires landing on valid BTI targets, significantly limiting available gadgets.

**Status:** enforced per-page via the GP (Guarded Page) bit in the page table entry. The kernel sets this for all executable pages compiled with BTI support.

## Comparison with x86

| Feature | ARM64 | x86 Equivalent | Status |
|---------|-------|----------------|--------|
| Return address signing | PAC (v8.3) | CET Shadow Stack | PAC: deployed. CET: limited adoption |
| Indirect branch protection | BTI (v8.5) | CET IBT | BTI: deployed. CET IBT: limited |
| Memory tagging | MTE (v8.5) | None (MPX deprecated) | MTE: limited HW. x86: nothing |
| Pointer signing | PAC | None | ARM64 unique |

ARM64 has a hardware security advantage for anti-cheat. The combination of PAC + BTI makes control-flow hijacking substantially harder than on x86, where CET adoption remains limited.
