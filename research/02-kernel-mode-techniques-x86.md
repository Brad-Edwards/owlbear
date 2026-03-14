# Kernel-Mode Anti-Cheat Techniques on x86/x86_64

## Driver Loading and Initialization

### Windows Driver Model
Anti-cheat drivers on Windows are typically WDM or KMDF drivers:

```c
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    // Create device object for userspace communication
    IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN,
                   FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
    IoCreateSymbolicLink(&symlinkName, &deviceName);

    // Register callbacks
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, FALSE);
    PsSetLoadImageNotifyRoutine(ImageLoadCallback);

    OB_CALLBACK_REGISTRATION obReg = { ... };
    ObRegisterCallbacks(&obReg, &callbackHandle);

    // Register minifilter for file system monitoring
    FltRegisterFilter(DriverObject, &filterRegistration, &filterHandle);
    FltStartFiltering(filterHandle);

    return STATUS_SUCCESS;
}
```

### Driver Signing Requirements
- Windows 10 1607+: kernel drivers must be signed by Microsoft's WHQL portal (attestation or HLK)
- EV code signing cert required to submit to WHQL
- Test signing (`bcdedit /set testsigning on`) disables Secure Boot — detectable
- Cross-signed drivers (legacy path) deprecated but some still load

### PatchGuard (KPP — Kernel Patch Protection)

PatchGuard monitors and BSODs on modification of:
- SSDT (System Service Descriptor Table)
- IDT (Interrupt Descriptor Table)
- GDT (Global Descriptor Table)
- MSR values (LSTAR, STAR, CSTAR — syscall entry points)
- Critical kernel code sections (`ntoskrnl.exe .text`)
- Processor control registers (CR0, CR4)
- Kernel object types

**Anti-cheat implications**: anti-cheats cannot use SSDT hooks or IDT hooks on modern Windows. They rely on documented callback mechanisms instead. However, *cheats* sometimes bypass PatchGuard to install stealth hooks.

PatchGuard check intervals are randomized (1-10 minutes), using DPC timer callbacks. Known bypass approaches:
1. Locate and patch the PatchGuard context structures in memory
2. Hook the DPC timer mechanism to intercept PatchGuard checks
3. Use hypervisor to redirect PatchGuard's memory reads to clean copies

## Memory Scanning Techniques

### Process Memory Enumeration
```c
// Walk virtual address space of target process
MEMORY_BASIC_INFORMATION mbi;
PVOID address = NULL;

while (NT_SUCCESS(ZwQueryVirtualMemory(processHandle, address,
        MemoryBasicInformation, &mbi, sizeof(mbi), NULL))) {
    if (mbi.State == MEM_COMMIT &&
        (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
        // Read and scan this region
        PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, mbi.RegionSize, 'scan');
        MmCopyVirtualMemory(targetProcess, address, PsGetCurrentProcess(),
                           buffer, mbi.RegionSize, KernelMode, &bytesRead);
        ScanBuffer(buffer, mbi.RegionSize);
        ExFreePool(buffer);
    }
    address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
}
```

### Signature Scanning Engine
Pattern matching typically uses a multi-pattern search algorithm (Aho-Corasick or similar):

```
Signature format examples:
  "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? FF 50 28"
   ^ specific bytes         ^ wildcards

  "E8 ?? ?? ?? ?? 84 C0 75 ?? 48 8B 0D"
   ^ CALL rel32 to unknown target, test AL, jnz short
```

Signatures target:
- Known cheat binary fragments
- Common cheat frameworks (e.g., Guided Hacking's injector patterns)
- Shellcode patterns (NOP sleds, common ROP gadgets)
- Memory manipulation patterns (VirtualAlloc + memcpy + VirtualProtect sequences)

### Module Detection — Beyond PEB Walking

Cheats often "unlink" their DLLs from PEB (Process Environment Block) loader lists:
```
PEB->Ldr->InLoadOrderModuleList
PEB->Ldr->InMemoryOrderModuleList
PEB->Ldr->InInitializationOrderModuleList
```

Anti-cheat counter-techniques:
1. **VAD walking**: traverse `VadRoot` in `EPROCESS` — VAD (Virtual Address Descriptor) tree is maintained by the memory manager, not the loader. Cannot be unlinked without corrupting memory management.
2. **Working set enumeration**: `MmGetWorkingSetInfo` — lists all physical pages mapped to the process
3. **Section object enumeration**: walk `SECTION_OBJECT_POINTERS` in `FILE_OBJECT` to find mapped files
4. **PE header scanning**: scan all committed memory regions for MZ/PE headers — finds manually mapped images

```c
// VAD-based module detection (simplified)
PMMVAD_SHORT vadRoot = (PMMVAD_SHORT)targetProcess->VadRoot.Root;
WalkVadTree(vadRoot, [](PMMVAD_SHORT vad) {
    if (vad->u.VadFlags.VadType == VadImageMap) {
        // This is a mapped image — check if it appears in PEB loader lists
        // If not, it's a hidden/manually mapped module
        PVOID baseAddress = (PVOID)(vad->StartingVpn << PAGE_SHIFT);
        if (!IsInLoaderList(baseAddress)) {
            ReportSuspiciousModule(baseAddress, vad->EndingVpn - vad->StartingVpn);
        }
    }
});
```

## Handle Interception

### Stripping Handle Access Rights

The primary defense against external memory manipulation:

```c
// ObRegisterCallbacks pre-operation handler
OB_PREOP_CALLBACK_STATUS HandlePreCallback(
    PVOID Context,
    POB_PRE_OPERATION_INFORMATION Info)
{
    if (Info->ObjectType != *PsProcessType &&
        Info->ObjectType != *PsThreadType)
        return OB_PREOP_SUCCESS;

    PEPROCESS target = (PEPROCESS)Info->Object;
    if (!IsProtectedProcess(target))
        return OB_PREOP_SUCCESS;

    PEPROCESS caller = IoGetCurrentProcess();
    if (IsAllowedProcess(caller))  // whitelist AC components, game launcher
        return OB_PREOP_SUCCESS;

    // Strip dangerous access rights
    ACCESS_MASK denyMask = PROCESS_VM_READ | PROCESS_VM_WRITE |
                           PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE |
                           PROCESS_CREATE_THREAD | PROCESS_SUSPEND_RESUME;

    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~denyMask;
    } else {  // OB_OPERATION_HANDLE_DUPLICATE
        Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~denyMask;
    }
    return OB_PREOP_SUCCESS;
}
```

### Bypasses Used by Cheats
- **BYOVD (Bring Your Own Vulnerable Driver)**: load a legitimately signed driver with known arbitrary read/write vulnerabilities:
  - `capcom.sys` — exposes IOCTL to execute arbitrary function pointer in kernel mode
  - `gdrv.sys` (GIGABYTE) — arbitrary physical memory read/write
  - `RTCore64.sys` (MSI) — arbitrary physical memory read/write via IOCTLs
  - `dbutil_2_3.sys` (Dell) — arbitrary kernel memory access
- **Direct physical memory**: `/dev/mem` equivalent via `\\.\PhysicalMemory` (blocked on modern Windows) or custom driver
- **DMA attacks**: use PCILeech / Screamer with FPGA-based PCIe device for physical memory access
- **Hypervisor-based**: run a thin hypervisor, intercept the anti-cheat's memory reads

## HVCI and VBS Implications

Virtualization-Based Security (VBS) on modern Windows:

- **HVCI (Hypervisor-Enforced Code Integrity)**: prevents unsigned code from executing in kernel mode
  - The hypervisor enforces W^X at the second-level page tables (EPT/NPT)
  - Kernel memory pages cannot be both writable AND executable
  - This breaks traditional kernel shellcode injection
- **Credential Guard**: isolates LSASS secrets — not directly AC-related but same VBS platform
- **Secure Kernel**: a separate kernel running in VTL1 (Virtual Trust Level 1) — anti-cheat runs in VTL0

Anti-cheat systems benefit from HVCI because:
1. Cheat drivers cannot allocate RWX kernel memory
2. Modifying existing kernel code pages requires EPT manipulation (only possible from hypervisor)
3. But HVCI adoption is still limited — many game PCs disable it for performance

## x86-Specific Considerations

### Debug Registers
x86 has 4 hardware breakpoint registers (DR0-DR3) with DR6 (status) and DR7 (control):
- Anti-cheat checks: read DR0-DR3 to detect hardware breakpoints on game functions
- Context: `GetThreadContext` / `NtGetContextThread` to read debug registers from userspace
- Kernel: direct register reads in driver
- Cheats use HW breakpoints for stealthy hooking (no code modification needed)

### MSR-Based Syscall Hooking
On x86_64, `SYSCALL` instruction reads `IA32_LSTAR` MSR for the kernel entry point:
```
MSR 0xC0000082 (LSTAR) → nt!KiSystemCall64
```
Anti-cheat monitors this MSR value. Cheats that redirect LSTAR to their own handler can intercept all system calls, but PatchGuard also monitors this.

### SMEP/SMAP
- **SMEP** (Supervisor Mode Execution Prevention): CPU faults if kernel tries to execute userspace pages (CR4 bit 20)
- **SMAP** (Supervisor Mode Access Prevention): CPU faults if kernel tries to read/write userspace pages without STAC/CLAC (CR4 bit 21)
- Anti-cheat verifies these bits are set — clearing them indicates tampering
- `CR4` is monitored by PatchGuard on Windows

### TSX-Based Timing Attacks
Intel TSX (Transactional Synchronization Extensions) was used for:
- **Timing kernel operations**: TSX transactions abort on interrupts, allowing measurement of kernel code execution time
- Useful for detecting if anti-cheat kernel callbacks are running
- Intel deprecated/disabled TSX on most CPUs post-2019 (Spectre/MDS mitigations)

## ETW (Event Tracing for Windows)

Modern anti-cheats increasingly use ETW providers for monitoring:

```
Microsoft-Windows-Kernel-Process    — process/thread lifecycle
Microsoft-Windows-Kernel-Audit-API  — sensitive API calls
Microsoft-Windows-Threat-Intelligence — special provider for security vendors
```

**`Microsoft-Windows-Threat-Intelligence` (TI) ETW Provider**:
- Only accessible to PPL (Protected Process Light) processes
- Provides notifications for:
  - `NtAllocateVirtualMemory` with executable permissions
  - `NtWriteVirtualMemory` (cross-process writes)
  - `NtMapViewOfSection` for remote mapping
  - `NtSetContextThread` (modifying thread context)
- This is how EDR products monitor for injection — anti-cheats can use the same if they run as PPL

## Minifilter I/O Interception

Anti-cheats use filesystem minifilters to:
1. Prevent cheats from modifying game files on disk
2. Detect cheat files being dropped to disk
3. Monitor DLL load paths for suspicious files

```c
FLT_PREOP_CALLBACK_STATUS PreCreateCallback(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION nameInfo;
    FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &nameInfo);
    FltParseFileNameInformation(nameInfo);

    // Block access to game files from non-whitelisted processes
    if (IsGameFile(&nameInfo->Name) && !IsAllowedCaller()) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_COMPLETE;
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}
```
