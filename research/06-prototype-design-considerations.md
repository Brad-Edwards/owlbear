# Prototype Design Considerations for ARM64 Kernel Anti-Cheat

## Target Platform Decisions

### Option A: ARM64 Linux (Recommended for Prototype)
- Full kernel source available
- Kernel module development well-documented
- eBPF tooling mature (libbpf, bpftool, CO-RE)
- Test on: Raspberry Pi 4/5, ARM cloud instances (AWS Graviton, Ampere Altra), Apple Silicon VM (Asahi Linux)
- Game target: any Linux-native game or a purpose-built test application

### Option B: Android (ARM64 Linux variant)
- Most common ARM64 gaming platform
- Additional constraints: SELinux enforcing, dm-verity, GKI (Generic Kernel Image)
- Would need to work within Android's module framework or use eBPF
- Relevant for mobile anti-cheat (very large real-world market)

### Option C: macOS (Apple Silicon)
- Very locked down: no third-party kexts since macOS 11, must use System Extensions
- Endpoint Security Framework (ESF) replaces kernel-level hooks
- Network Extension / Driver Extension frameworks
- Useful to study but poor prototype target due to restrictions

**Recommendation**: ARM64 Linux on Graviton or Pi, with a purpose-built "game" test application. This gives full kernel access and matches the technical depth needed.

## Prototype Scope — What to Build

### Phase 1: Foundation (Kernel Module + Basic Monitoring)
Deliverables:
1. Loadable kernel module for ARM64 Linux
2. Character device for userspace communication
3. Process creation/termination monitoring (tracepoints)
4. Basic ptrace protection for a target process
5. Userspace daemon that receives events and logs them

What this proves: you can load code into the kernel, monitor process activity, and communicate findings to userspace.

### Phase 2: Memory Protection
Deliverables:
1. Block /proc/[pid]/mem access to protected process
2. Block process_vm_readv/writev to protected process
3. Monitor mmap calls with PROT_EXEC in protected process
4. Detect and report loaded kernel modules
5. ARM64 system register snapshot and verification

What this proves: you can prevent the primary external memory access vectors and detect kernel-level tampering.

### Phase 3: Integrity Verification
Deliverables:
1. Code section hashing of protected binary at load time
2. Periodic re-verification of code integrity
3. Loaded shared library enumeration and verification
4. Debug register monitoring (DBGBCR/DBGBVR, DBGWCR/DBGWVR)
5. PAC key integrity verification (if hardware supports it)

What this proves: you can detect in-memory code modification (patches, hooks) and hardware-level debugging.

### Phase 4: eBPF Integration
Deliverables:
1. eBPF programs for LSM hooks (ptrace, file_open, mmap)
2. eBPF programs for syscall monitoring (tracepoints)
3. Ring buffer event pipeline to userspace
4. Policy engine: configurable rules for what to monitor/block
5. Hybrid operation: eBPF + kernel module working together

What this proves: you can build a modern, maintainable monitoring infrastructure alongside hardware-level checks.

### Phase 5: Advanced Detection
Deliverables:
1. Signature scanning engine (pattern matching in process memory)
2. Behavioral analysis: input timing, memory access patterns
3. Environment attestation: Secure Boot status, kernel integrity
4. Heartbeat/watchdog system
5. Tamper resistance for the anti-cheat itself

## Test Application ("Game")

Build a minimal test application that simulates cheat-relevant game internals:

```c
// Minimal "game" structure for testing
struct game_state {
    int player_health;        // Target for value modification
    float player_pos[3];      // Target for teleport/speedhack
    float aim_angles[2];      // Target for aimbot
    void (*damage_func)(int); // Target for function hooking
    void *vtable;             // Target for vtable hooks
};

// The "game" should:
// 1. Maintain mutable state (health, position, aim)
// 2. Have function pointers that can be hooked
// 3. Use shared libraries (to test library verification)
// 4. Render something simple (even terminal output) to verify liveness
// 5. Accept input (to test input validation)
// 6. Communicate with the anti-cheat (register itself, report status)
```

Also build test "cheats" to validate detection:
- External memory reader (uses process_vm_readv)
- ptrace-based injector
- /proc/pid/mem reader
- LD_PRELOAD-based hook
- Kernel module that reads game memory via direct physical access
- Debug register setter

## Development Environment

### Build Requirements
```
# Cross-compilation (if developing on x86)
aarch64-linux-gnu-gcc          # ARM64 cross compiler
linux-headers-arm64            # Kernel headers for module building

# Native ARM64 development
gcc / clang                    # Native compiler
linux-headers-$(uname -r)     # Kernel headers
libbpf-dev                    # eBPF library
clang + llvm                  # BPF program compilation
bpftool                       # BPF program management

# Testing
qemu-system-aarch64           # ARM64 VM (if no hardware)
buildroot / yocto             # Custom kernel/rootfs for testing
```

### Kernel Configuration
Required kernel config options:
```
CONFIG_MODULES=y               # Loadable modules
CONFIG_MODULE_SIG=y            # Module signing (optional for dev)
CONFIG_KPROBES=y               # Kprobes support
CONFIG_BPF=y                   # BPF support
CONFIG_BPF_SYSCALL=y           # BPF syscall
CONFIG_BPF_JIT=y               # BPF JIT for ARM64
CONFIG_BPF_LSM=y               # BPF LSM hooks
CONFIG_DEBUG_INFO_BTF=y        # BTF for CO-RE
CONFIG_TRACEPOINTS=y           # Tracepoint support
CONFIG_FTRACE=y                # Function tracing
CONFIG_ARM64_PTR_AUTH=y        # Pointer Authentication
CONFIG_ARM64_MTE=y             # Memory Tagging (if HW supports)
CONFIG_ARM64_BTI=y             # Branch Target Identification
```

## Key Design Decisions

### 1. Kernel Module vs eBPF-Only
- Pure eBPF: safer, more portable, but limited (no hardware register access)
- Pure kernel module: full power but harder to maintain, riskier
- **Hybrid recommended**: eBPF for monitoring, kernel module for hardware-specific checks

### 2. Enforcement Model
- **Observe-only**: log suspicious activity but don't block (good for development/tuning)
- **Block-and-log**: deny specific operations (ptrace, memory access) while logging
- **Kill-on-detect**: terminate the game if cheat detected (production behavior)
- **Recommendation**: start observe-only, add enforcement gradually

### 3. Communication Architecture
- **Netlink**: standard kernel-userspace communication, well-supported
- **Character device + ioctl**: simple, well-understood
- **BPF ring buffer**: high-performance, zero-copy for eBPF events
- **Recommendation**: BPF ring buffer for eBPF events, chardev+ioctl for kernel module control

### 4. Signature vs Behavioral Detection
- Signatures are brittle but have zero false positives on known cheats
- Behavioral detection catches unknown cheats but has false positive risk
- **Recommendation**: implement both, use signatures for known threats and behavioral for zero-day detection

## Threat Model for Prototype

Assume the adversary (cheat developer) has:
- Root access on the system (common for Linux gaming PCs)
- Ability to load kernel modules (if secure boot disabled)
- Knowledge of anti-cheat techniques and common bypasses
- Access to game memory from userspace and kernel space
- Hardware debugging tools (JTAG, SWD for ARM64)

Anti-cheat goals:
1. Raise the bar: make cheating require more skill/effort than the game is worth
2. Detect known techniques: signature-based detection for common cheats
3. Detect novel techniques: behavioral analysis for unknown cheats
4. Resist tampering: make it hard to disable/bypass the anti-cheat itself
5. Report findings: communicate detections to a server for enforcement

Non-goals for prototype:
- Ban enforcement infrastructure (server-side, out of scope)
- Hardware fingerprinting/HWID bans (complex, privacy-sensitive)
- Anti-analysis for the anti-cheat itself (obfuscation, anti-debug)
- DRM or software licensing integration

## Interview-Relevant Architecture Discussion Points

Topics a senior PM anti-cheat interviewer would probe:

1. **Privacy vs security trade-off**: kernel anti-cheat has access to everything on the system. How do you limit data collection to only game-relevant information? How do you handle GDPR/privacy regulations?

2. **Performance impact**: kernel callbacks add latency to every process creation, file open, etc. How do you minimize impact? (Answer: early-exit checks, per-CPU data structures, BPF map lookups are O(1))

3. **False positive management**: how do you handle legitimate software (OBS, Discord overlay, accessibility tools) that triggers heuristic detections? (Answer: whitelisting, tunable thresholds, observe-mode before enforcement)

4. **Update cadence**: cheat developers release updates within hours of anti-cheat updates. How do you maintain detection without pushing kernel driver updates? (Answer: server-side signature updates, eBPF programs can be updated without driver reload, behavioral detection doesn't need frequent updates)

5. **Kernel driver risks**: a bug in a kernel driver can BSOD/panic the system. How do you mitigate this? (Answer: extensive testing, fuzz testing, eBPF verifier for BPF components, staged rollout, kill switch)

6. **Boot-time vs game-time loading**: Vanguard loads at boot, EAC loads at game launch. Trade-offs? (Answer: boot-time gives stronger trust anchor but higher user friction and broader system impact. Game-time is less invasive but cheats can establish position before anti-cheat loads)

7. **Hardware-level attacks (DMA, FPGA)**: these operate below the OS. What can a kernel anti-cheat do? (Answer: verify IOMMU/SMMU is enabled, monitor PCIe device enumeration, timing analysis, but fundamentally limited — need hardware-level mitigations)

8. **Linux vs Windows anti-cheat differences**: no PatchGuard on Linux (so cheats can hook anything), but also more transparency (open kernel source). SELinux/AppArmor provide additional policy enforcement not available on Windows.

9. **ARM vs x86 anti-cheat differences**: PAC/MTE/BTI give ARM64 hardware-level protections that don't exist on x86. Non-coherent I/D caches make code injection detectable. But ARM64 gaming is smaller market, so less battle-tested.

10. **Measuring effectiveness**: how do you know if anti-cheat is working? (Answer: cheat detection rate, time-to-detect for new cheats, false positive rate, performance impact metrics, player sentiment surveys, ban appeal rate)
