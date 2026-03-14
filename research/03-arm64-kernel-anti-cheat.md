# ARM64 Kernel-Mode Anti-Cheat: Architecture and Techniques

## ARM64 vs x86_64 — Fundamental Differences for Anti-Cheat

### Exception Levels (ARM's Privilege Rings)

```
EL3 — Secure Monitor (firmware/TrustZone monitor)
EL2 — Hypervisor
EL1 — Kernel (OS)
EL0 — Userspace (applications)
```

Key differences from x86 ring model:
- ARM has a clean separation of exception levels with no legacy baggage
- TrustZone (EL3 + Secure World) provides a hardware-isolated execution environment with no x86 equivalent
- No equivalent to x86's SMM (System Management Mode) — EL3 replaces this
- Hypervisor (EL2) is cleanly separated, not bolted on like VT-x/AMD-V

### System Register Architecture

ARM64 uses system registers (accessed via MRS/MSR instructions) instead of x86 MSRs:

```
SCTLR_EL1   — System Control Register (equivalent to x86 CR0)
TCR_EL1     — Translation Control Register (MMU configuration)
TTBR0_EL1   — Translation Table Base 0 (user page tables, ~ x86 CR3 lower half)
TTBR1_EL1   — Translation Table Base 1 (kernel page tables, ~ x86 CR3 upper half)
VBAR_EL1    — Vector Base Address Register (exception/interrupt vector table base)
MDSCR_EL1   — Monitor Debug System Control Register
HCR_EL2     — Hypervisor Configuration Register
```

For anti-cheat, the important difference: ARM64 uses two separate page table bases (TTBR0 for user, TTBR1 for kernel), which has implications for Spectre mitigations and kernel memory isolation.

### Memory Architecture Differences

ARM64 page table format:
- 4KB, 16KB, or 64KB granules (x86: always 4KB base)
- 4-level page tables (like x86_64): PGD, PUD, PMD, PTE
- Translation Table Walk: hardware page table walker, similar to x86
- Attribute bits differ:
  - UXN (User Execute Never) / PXN (Privileged Execute Never) — equivalent to x86 NX/XD but more granular
  - AP[2:1] — access permission bits (read/write/EL0 access)
  - SH — shareability (inner/outer) — relevant for cache coherency on multi-cluster ARM SoCs

Memory Tagging Extension (MTE, ARMv8.5+):
- Hardware memory tagging with 4-bit tags in top byte of pointers
- Each 16-byte memory granule has an associated 4-bit tag
- Tag mismatch triggers synchronous/asynchronous exception
- Anti-cheat application: detect buffer overflows and use-after-free in game process
- Can also be used to tag and verify critical game data structures

Pointer Authentication (PAC, ARMv8.3+):
- CPU signs pointers using a key + context (e.g., stack pointer)
- Signature stored in unused upper bits of 64-bit pointer
- PACIA / AUTIA instructions to sign/verify
- Anti-cheat implications:
  - Return addresses on stack are signed, making ROP much harder
  - Function pointers can be signed, making vtable hijacking harder
  - Anti-cheat can use PAC to protect its own data structures
  - Cheats cannot forge valid signed pointers without the key

BTI (Branch Target Identification, ARMv8.5+):
- Only BTI landing pad instructions valid for indirect branch targets
- Equivalent to x86 CET-IBT (Indirect Branch Tracking)
- Prevents JOP (Jump-Oriented Programming) attacks

## Linux Kernel Module Architecture (ARM64 Anti-Cheat)

Since most ARM64 anti-cheat targets Linux (Android, Linux gaming via Proton, Apple Silicon via macOS — though macOS requires different approaches), the kernel module interface differs from Windows:

### Loading a Kernel Module

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>

static int __init owlbear_init(void) {
    pr_info("owlbear: initializing anti-cheat driver\n");

    register_process_monitor();
    register_memory_monitor();
    register_module_monitor();

    owlbear_create_chardev();

    return 0;
}

static void __exit owlbear_exit(void) {
    unregister_process_monitor();
    unregister_memory_monitor();
    unregister_module_monitor();
    owlbear_destroy_chardev();
}

module_init(owlbear_init);
module_exit(owlbear_exit);
MODULE_LICENSE("GPL");
```

### Module Signing on Linux
- CONFIG_MODULE_SIG_FORCE: kernel rejects unsigned modules
- Modules signed with kernel build key (embedded in kernel image)
- Secure Boot + shim + MOK (Machine Owner Key) chain on UEFI systems
- Android: modules must be signed + dm-verity protects system partition

### Process Monitoring on Linux

No direct equivalent of Windows PsSetCreateProcessNotifyRoutineEx. Options:

**1. Kprobes / Kretprobes**
```c
static struct kprobe fork_probe = {
    .symbol_name = "kernel_clone",
};

static int fork_pre_handler(struct kprobe *p, struct pt_regs *regs) {
    // ARM64: arguments in x0-x7
    struct kernel_clone_args *args = (void *)regs->regs[0];
    return 0;
}
```

**2. Tracepoints**
```c
register_trace_sched_process_fork(fork_callback, NULL);
register_trace_sched_process_exec(exec_callback, NULL);
register_trace_sched_process_exit(exit_callback, NULL);
```

**3. LSM (Linux Security Module) hooks** — most robust approach:
```c
static struct security_hook_list owlbear_hooks[] = {
    LSM_HOOK_INIT(bprm_check_security, owlbear_bprm_check),
    LSM_HOOK_INIT(ptrace_access_check, owlbear_ptrace_check),
    LSM_HOOK_INIT(mmap_file, owlbear_mmap_check),
    LSM_HOOK_INIT(file_open, owlbear_file_open),
};
```

LSM hooks are the gold standard but historically required compile-time registration. Since Linux 5.x, BPF LSM allows runtime attachment.

**4. eBPF-based monitoring** (modern approach):
```c
SEC("lsm/bprm_check_security")
int BPF_PROG(check_exec, struct linux_binprm *bprm, int ret) {
    char filename[256];
    bpf_d_path(&bprm->file->f_path, filename, sizeof(filename));
    return 0;
}
```

### Memory Protection on ARM64 Linux

Preventing ptrace-based memory access:
```c
static int owlbear_ptrace_check(struct task_struct *child, unsigned int mode) {
    if (is_protected_game(child)) {
        if (!is_allowed_debugger(current)) {
            return -EPERM;
        }
    }
    return 0;
}
```

Monitoring /proc/[pid]/mem access (the Linux equivalent of ReadProcessMemory):
```c
static int owlbear_file_open(struct file *file) {
    struct path *path = &file->f_path;
    if (is_proc_mem_access(path) && is_protected_pid(path)) {
        return -EACCES;
    }
    return 0;
}
```

Also must monitor process_vm_readv / process_vm_writev — cross-process memory access syscalls that work without ptrace attachment.

## ARM64-Specific Detection Techniques

### 1. Exception Vector Table Monitoring

ARM64 exception vectors are at VBAR_EL1:

```
Offset 0x000: Synchronous, current EL, SP_EL0
Offset 0x080: IRQ, current EL, SP_EL0
Offset 0x100: FIQ, current EL, SP_EL0
Offset 0x180: SError, current EL, SP_EL0
Offset 0x200: Synchronous, current EL, SP_ELx
Offset 0x280: IRQ, current EL, SP_ELx
...
Offset 0x400: Synchronous, lower EL, AArch64
Offset 0x480: IRQ, lower EL, AArch64
...
```

Anti-cheat should:
1. Read VBAR_EL1 and verify it points to the expected kernel vector table
2. Hash the vector table contents and compare against known-good values
3. Detect if cheat has redirected exception vectors

```c
static bool verify_vector_table(void) {
    u64 vbar;
    asm volatile("mrs %0, vbar_el1" : "=r"(vbar));

    if (vbar != (u64)vectors) {
        report_tamper("VBAR_EL1 modified: expected %llx, got %llx",
                     (u64)vectors, vbar);
        return false;
    }

    u8 hash[SHA256_DIGEST_SIZE];
    sha256((void *)vbar, VECTOR_TABLE_SIZE, hash);
    return memcmp(hash, expected_vector_hash, SHA256_DIGEST_SIZE) == 0;
}
```

### 2. System Register Integrity Checks

```c
struct sysreg_snapshot {
    u64 sctlr_el1;
    u64 tcr_el1;
    u64 mair_el1;
    u64 mdscr_el1;
};

static void check_sysregs(void) {
    struct sysreg_snapshot current;

    asm volatile(
        "mrs %0, sctlr_el1\n"
        "mrs %1, tcr_el1\n"
        "mrs %2, mair_el1\n"
        "mrs %3, mdscr_el1\n"
        : "=r"(current.sctlr_el1),
          "=r"(current.tcr_el1),
          "=r"(current.mair_el1),
          "=r"(current.mdscr_el1)
    );

    // SCTLR_EL1 bit checks:
    // Bit 0 (M):   MMU must be enabled
    // Bit 2 (C):   Data cache must be enabled
    // Bit 12 (I):  Instruction cache must be enabled
    // Bit 19 (WXN): Write implies Execute Never — should be set
    // Bit 25 (EE):  Endianness — should match expected

    if (!(current.sctlr_el1 & SCTLR_EL1_WXN)) {
        report_tamper("WXN disabled — W+X pages possible");
    }

    // Check MDSCR_EL1 for debug enable
    // Bit 13 (MDE): Monitor Debug Enable
    // Bit 15 (KDE): Kernel Debug Enable
    if (current.mdscr_el1 & (MDSCR_MDE | MDSCR_KDE)) {
        report_debug("Hardware debug enabled in MDSCR_EL1");
    }
}
```

### 3. Hardware Debug Register Monitoring

ARM64 has up to 16 hardware breakpoints and 16 watchpoints:

```c
static void check_debug_registers(void) {
    u64 dbgbcr[16], dbgbvr[16];
    u64 dbgwcr[16], dbgwvr[16];

    asm volatile("mrs %0, dbgbcr0_el1" : "=r"(dbgbcr[0]));
    asm volatile("mrs %0, dbgbvr0_el1" : "=r"(dbgbvr[0]));
    // ... repeat for all registers

    for (int i = 0; i < 16; i++) {
        if (dbgbcr[i] & 1) {
            report_debug("Hardware breakpoint %d active at %llx", i, dbgbvr[i]);
            if (is_game_code_region(dbgbvr[i])) {
                report_cheat("HW breakpoint on game code at %llx", dbgbvr[i]);
            }
        }
        if (dbgwcr[i] & 1) {
            report_debug("Hardware watchpoint %d active at %llx", i, dbgwvr[i]);
        }
    }
}
```

### 4. PAC (Pointer Authentication) Integrity Verification

```c
static void check_pac_integrity(void) {
    u64 apiakeyhi, apiakeylo;
    u64 apibkeyhi, apibkeylo;
    u64 apdakeyhi, apdakeylo;

    asm volatile(
        "mrs %0, apiakeyhi_el1\n"
        "mrs %1, apiakeylo_el1\n"
        : "=r"(apiakeyhi), "=r"(apiakeylo)
    );

    if (apiakeyhi != saved_apiakeyhi || apiakeylo != saved_apiakeylo) {
        report_tamper("PAC IA key changed — potential key substitution attack");
    }

    u64 sctlr;
    asm volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    if (!(sctlr & SCTLR_EL1_EnIA)) {
        report_tamper("PAC instruction authentication disabled");
    }
}
```

### 5. Kernel Code Integrity via MTE

On ARMv8.5+ with MTE support:
```c
static void protect_game_data(void *data, size_t size) {
    u8 tag = get_random_tag();
    void *tagged_ptr = __arm_mte_set_tag(data, tag);

    // Any unauthorized modification that doesn't preserve tags
    // will cause a tag check fault
}
```

### 6. Cache Maintenance Monitoring

ARM64 has explicit cache maintenance instructions that can reveal cheat activity:

```
DC CIVAC  — Clean and Invalidate by VA to Point of Coherency
DC CVAU   — Clean by VA to Point of Unification
IC IVAU   — Invalidate Instruction cache by VA to Point of Unification
```

Cheats modifying code in memory must use IC IVAU + ISB to flush instruction cache (ARM has non-coherent I/D caches, unlike x86). This can be trapped if running under a hypervisor (HCR_EL2.TPC/TPU bits).

### 7. TrustZone Integration (Advanced)

ARM TrustZone provides a hardware-isolated Secure World:

```
Normal World (NS=1)              Secure World (NS=0)
+--------------------+           +--------------------+
| EL0: Game App      |           | S-EL0: Trusted App |
| EL1: Linux/AC      |  --SMC->  |                   |
| EL2: Hypervisor    |           | S-EL1: Secure OS   |
|                    |           |        (OP-TEE)     |
+--------------------+           +--------------------+
                     <--- EL3: Secure Monitor --->
```

Anti-cheat can use TrustZone to:
1. Store integrity measurements in Secure World (inaccessible from Normal World)
2. Run integrity verification code in S-EL1/S-EL0 (tamper-proof)
3. Use Secure Memory (TZC-400 controller) for sensitive anti-cheat data
4. Cryptographic key storage in hardware-isolated secure storage

```c
struct integrity_result {
    u64 code_hash;
    u64 data_hash;
    u32 status;
};

static int verify_via_trustzone(struct integrity_result *result) {
    struct arm_smccc_res smc_result;

    arm_smccc_smc(
        OWLBEAR_TA_VERIFY_INTEGRITY,
        game_code_base,
        game_code_size,
        game_data_base,
        0, 0, 0, 0,
        &smc_result
    );

    result->status = smc_result.a0;
    result->code_hash = smc_result.a1;
    result->data_hash = smc_result.a2;
    return (result->status == INTEGRITY_OK) ? 0 : -1;
}
```

## ARM64 Page Table Manipulation for Anti-Cheat

### Setting Memory Protections

ARM64 PTE bits relevant to anti-cheat:

```
Bit 0     — Valid (entry is valid)
Bit 1     — Table (table descriptor for non-leaf)
Bit 10    — AF (Access Flag)
Bit 7     — AP[2] (Read-only when set)
Bit 6     — AP[1] (EL0 accessible when set)
Bit 54    — UXN (User Execute Never)
Bit 53    — PXN (Privileged Execute Never)
Bit 51    — DBM (Dirty Bit Modifier, ARMv8.1)
Bit 50    — GP (Guarded Page for BTI, ARMv8.5)
```

```c
static void protect_game_code_pages(unsigned long start, unsigned long end) {
    pte_t *pte;

    for (unsigned long addr = start; addr < end; addr += PAGE_SIZE) {
        pte = lookup_pte(current->mm, addr);
        if (pte) {
            pte_t new_pte = pte_wrprotect(*pte);
            new_pte = pte_mkclean(new_pte);
            set_pte_at(current->mm, addr, pte, new_pte);
        }
    }
    flush_tlb_range(current->mm, start, end);
}
```

### Two-Stage Translation (EL2) for Memory Isolation

ARM64 Stage-2 translation (controlled by hypervisor at EL2) provides:

```
Stage 1 (EL1):  VA -> IPA (Intermediate Physical Address)
Stage 2 (EL2):  IPA -> PA (Physical Address)
Combined: VA -> IPA -> PA
```

This is equivalent to x86 EPT (Extended Page Tables). Anti-cheat hypervisor can:
1. Mark game physical pages as non-readable from other contexts at Stage-2
2. Detect DMA attacks by controlling Stage-2 translations for device memory regions
3. Trap accesses to specific memory regions for monitoring

## ARM64 Performance Monitoring for Cheat Detection

ARM64 PMU (Performance Monitoring Unit) can detect anomalous behavior:

```c
static void setup_pmu_monitoring(void) {
    u64 events[] = {
        0x08,   // INST_RETIRED
        0x13,   // MEM_ACCESS
        0x1B,   // INST_SPEC (speculatively executed)
        0x3A,   // STALL_FRONTEND
    };

    asm volatile("msr pmcr_el0, %0" :: "r"(PMCR_E | PMCR_LC | PMCR_C));

    for (int i = 0; i < ARRAY_SIZE(events); i++) {
        // Configure event counters
    }

    asm volatile("msr pmcntenset_el0, %0" :: "r"(0xF));

    // Periodically sample and look for anomalies:
    // - Abnormal instruction retirement rate (aimbot tight loops)
    // - Excessive memory accesses (wallhack memory scanning)
    // - Cache miss patterns inconsistent with normal gameplay
}
```

## Differences from x86 Anti-Cheat — Summary Table

| Aspect | x86_64 | ARM64 |
|--------|--------|-------|
| Privilege levels | Ring 0-3 + SMM | EL0-EL3 + Secure World |
| Page tables | Single CR3 | Split TTBR0/TTBR1 |
| I/D cache coherency | Coherent (snoop) | Non-coherent (explicit maintenance) |
| Return address protection | Shadow stack (CET) | PAC (pointer signing) |
| Indirect branch protection | IBT (CET) | BTI |
| Memory tagging | None (MPX deprecated) | MTE (ARMv8.5) |
| Debug breakpoints | 4 HW breakpoints | Up to 16 breakpoints + 16 watchpoints |
| Kernel patch protection | PatchGuard (Windows) | None built-in (varies by OS) |
| Hypervisor extensions | VT-x / AMD-V + EPT/NPT | EL2 + Stage-2 translation |
| Trusted execution | SGX (deprecated), TDX | TrustZone + CCA (ARMv9) |
| Syscall mechanism | SYSCALL/SYSENTER | SVC (EL0->EL1), HVC (EL1->EL2), SMC (->EL3) |
| Code modification detection | Hash comparison | Hash + I-cache flush requirement |
| DMA protection | IOMMU/VT-d | SMMU (System MMU) |
