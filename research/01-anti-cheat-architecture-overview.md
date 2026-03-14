# Anti-Cheat System Architecture: Technical Deep Dive

## Layered Trust Model

Modern anti-cheat operates across four privilege layers, each providing different detection capabilities:

```
Ring -1  (Hypervisor)    — Platform-provided (Windows VBS/Hyper-V). No major AC ships its own
                           hypervisor; they *leverage* Ring -1 when available (HVCI, EPT protections)
Ring 0   (Kernel)        — Where all major ACs actually run: driver-level hooks, callback
                           registration, memory scanning, driver blocklisting
Ring 3   (Userspace)     — Process instrumentation, overlay detection, input validation
Ring 3+  (Remote/Server) — Statistical anomaly detection, replay validation, server-side checks
```

**Important distinction**: EAC, BattlEye, Vanguard, and Javelin all operate at Ring 0 (kernel mode). None deploy their own hypervisor at Ring -1. They *benefit from* the platform's hypervisor when available — e.g., Vanguard leverages HVCI to prevent unsigned kernel code execution, and checks that VBS is enabled to strengthen its trust model. But the anti-cheat driver itself runs at Ring 0, not Ring -1.

The fundamental problem: cheats that run at equal or higher privilege than the anti-cheat are invisible to it. This is why the industry moved from userspace-only (PunkBuster era) to kernel-mode (EAC, BattlEye, Vanguard, Javelin).

## Major Commercial Systems — Architecture Breakdown

### Easy Anti-Cheat (EAC)
- **Kernel driver**: `EasyAntiCheat.sys` / `easyanticheat.ko`
- Registers `PsSetCreateProcessNotifyRoutineEx` callback to monitor process creation
- Registers `ObRegisterCallbacks` on process/thread object types to intercept handle operations
- Uses `MmCopyVirtualMemory` monitoring via hooking or ETW to detect cross-process reads
- Heartbeat system: kernel driver sends signed telemetry to userspace service, which relays to EAC servers
- **Integrity**: driver is signed with EV cert + attestation blob verified server-side
- Maps a userspace module into the game process that hooks `NtQueryVirtualMemory`, `NtReadVirtualMemory` to detect debuggers

### BattlEye (BE)
- **Kernel driver**: `BEDaisy.sys`
- Heavier on kernel-mode scanning: walks `EPROCESS` lists to detect hidden processes
- Scans loaded driver list (`PsLoadedModuleList`) for unsigned/suspicious drivers
- Monitors `KeServiceDescriptorTable` (SSDT) for hooks on x86 (less relevant post-PatchGuard)
- Userspace shellcode injection: BE injects position-independent code (not a DLL) into the game process
  - This shellcode scans game memory for known cheat signatures
  - Communicates with kernel driver via shared memory section, not IOCTLs (harder to intercept)
- Periodic memory dumps sent server-side for deeper analysis

### Riot Vanguard
- **Kernel driver**: `vgk.sys` — loads at **boot time** (not game launch)
- This is the key differentiator: by loading before any cheat, it establishes a trust anchor
- Uses `CmRegisterCallbackEx` to monitor registry modifications
- Monitors driver loads via `PsSetLoadImageNotifyRoutine`
- Blocks known-vulnerable drivers from loading (BYOVD prevention)
- Leverages Windows VBS/HVCI when available:
  - Benefits from HVCI preventing unsigned kernel code execution
  - Uses platform hypervisor's EPT protections for memory attestation
  - Does NOT ship its own hypervisor — relies on the Windows hypervisor (Hyper-V/VBS)
  - Detects DMA attacks by monitoring IOMMU configuration

### EA Javelin
- **EA's proprietary in-house anti-cheat** — used in Battlefield 6, Apex Legends, EA Sports FC
- **Kernel driver**: loads at boot time (same approach as Vanguard, not at game launch)
- **Secure Boot hard requirement**: refuses to run if Secure Boot is disabled — establishes a
  verified boot chain before the driver loads. This killed initial Steam Deck/Linux support.
- **Driver blocklisting**: actively blocks known-vulnerable, unsigned, or HVCI-incompatible
  drivers from coexisting on the system (BYOVD prevention). If a deny-listed driver is loaded,
  Javelin refuses to let the game launch.
- **HVCI compatibility enforcement**: verifies that loaded drivers are compatible with
  Hypervisor-Protected Code Integrity — leverages the platform's Ring -1 protections
- **Boot-time trust anchor**: because it loads with Windows, it can detect cheats that try to
  hook into memory or GPU drivers before the game process starts
- Claimed 300,000 cheat attempts blocked in 2 days during BF6 beta
- **ARM64 expansion**: EA is actively developing a native ARM64 Windows kernel driver for
  Javelin (not an emulated x86 shim) — requires ground-up rework of memory barriers, atomics,
  and architecture-specific memory management. Directly relevant to our prototype.
- **Linux/Steam Deck support**: also under active development, indicating EA sees cross-platform
  kernel anti-cheat as a strategic investment

## Detection Taxonomy

### 1. Signature-Based Detection
- Byte pattern scanning of process memory (game + loaded modules)
- Yara-like rule matching against known cheat binaries
- Import table analysis — cheats often import `WriteProcessMemory`, `VirtualAllocEx`, `NtSuspendThread`
- String scanning for known cheat UI frameworks (Dear ImGui signatures, etc.)
- **Limitation**: trivially bypassed by polymorphic cheats, packers, or manual mapping

### 2. Integrity Verification
- **Code integrity**: hash `.text` sections of game executable and critical DLLs at load time, periodically re-verify
- **Hook detection**: walk IAT/EAT of game modules, compare function prologues against on-disk images
  - Detect inline hooks: `JMP` / `CALL` instructions at function entry points
  - Detect IAT hooks: pointer comparisons against expected module ranges
- **Stack walking**: verify return addresses on the call stack point to legitimate code regions
- **Module verification**: enumerate loaded modules via `LdrpModuleBaseAddressIndex` (not just PEB->Ldr, which is easily unlinked)

### 3. Behavioral Detection
- **Timing analysis**: measure frame-to-input latency; aimbots produce unnaturally consistent reaction times
- **Input validation**: compare raw hardware input (from HID driver) against processed game input
  - Detects input injection (SendInput, mouse_event, driver-level injection)
- **Memory access patterns**: monitor page faults and working set changes — external readers cause distinctive patterns
- **Handle auditing**: enumerate all handles to the game process via `NtQuerySystemInformation(SystemHandleInformation)`

### 4. Environment Attestation
- **TPM-based**: read PCR values to verify boot chain integrity
- **Secure boot verification**: ensure no test-signing or unsigned driver loading
- **Hypervisor detection**: CPUID leaf checks, timing-based detection of nested virtualization
- **Hardware ID**: combine disk serial, MAC, TPM EK, SMBIOS UUID for hardware fingerprinting (used for ban enforcement)

## Kernel Callback Infrastructure (Windows NT)

These are the primary kernel APIs anti-cheats register with:

```
PsSetCreateProcessNotifyRoutineEx    — process creation/termination
PsSetCreateThreadNotifyRoutine       — thread creation in any process
PsSetLoadImageNotifyRoutine          — image (DLL/driver) loads
ObRegisterCallbacks                  — handle operations (open/duplicate)
CmRegisterCallbackEx                 — registry operations
MiniFilter (FltRegisterFilter)       — filesystem I/O interception
IoRegisterFsRegistrationChange       — filesystem driver registration
```

### ObRegisterCallbacks — The Handle Gate

This is arguably the most critical anti-cheat callback. It intercepts `NtOpenProcess` / `NtDuplicateObject`:

```c
OB_PREOP_CALLBACK_STATUS PreOperationCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperInfo
) {
    if (OperInfo->ObjectType == *PsProcessType) {
        // Strip PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_VM_OPERATION
        // from any handle being opened to the protected game process
        if (IsProtectedProcess(OperInfo->Object)) {
            OperInfo->Parameters->CreateHandleInformation.DesiredAccess &=
                ~(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
        }
    }
    return OB_PREOP_SUCCESS;
}
```

This prevents external processes from reading/writing game memory via `ReadProcessMemory` / `WriteProcessMemory`. Cheats bypass this by:
- Mapping a vulnerable driver to call `MmCopyVirtualMemory` directly (BYOVD)
- Using DMA (PCIe devices that read physical memory directly)
- Abusing legitimate signed drivers with read/write primitives

## Communication Channels

Anti-cheat needs to communicate between kernel, userspace, and remote server:

```
Kernel ←→ Userspace:
  - IOCTLs via DeviceIoControl (most common, easily monitored by cheats)
  - Shared memory sections (NtCreateSection + NtMapViewOfSection)
  - Named pipes
  - Filter communication ports (FltCreateCommunicationPort) — used by minifilter-based ACs

Userspace ←→ Server:
  - TLS 1.3 with certificate pinning
  - Custom binary protocol over TCP/UDP
  - Heartbeat packets (typically 5-30 second interval)
  - Telemetry batches (memory scan results, process lists, driver lists)
  - Challenge-response for client integrity verification
```

## Anti-Tamper for the Anti-Cheat Itself

The anti-cheat must protect itself from being disabled:

- **Self-integrity**: kernel driver periodically hashes its own `.text` section
- **Thread protection**: registers thread callbacks, detects if AC threads are suspended/terminated
- **Handle protection**: uses `ObRegisterCallbacks` on its own process to prevent handle access
- **Service protection**: registers as a Protected Process Light (PPL) on Windows — `svchost -k` with AM-PPL signer level
- **Watchdog**: separate process/thread that monitors the main AC process; if it dies, kill the game
- **Encrypted IPC**: communication between AC components uses session keys derived from hardware-bound secrets
