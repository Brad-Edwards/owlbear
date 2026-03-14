# Cheat Techniques and Anti-Cheat Bypasses — Technical Reference

Understanding what the anti-cheat must defend against. This is structured by attack vector.

## 1. External Memory Access (Read/Write Another Process)

### Userspace Methods (Easiest to Detect)

**ReadProcessMemory / WriteProcessMemory (Windows)**:
- Requires PROCESS_VM_READ/WRITE handle access
- Blocked by ObRegisterCallbacks handle stripping
- Detection: enumerate handles to game process via NtQuerySystemInformation(SystemHandleInformation)

**process_vm_readv / process_vm_writev (Linux)**:
- Direct cross-process memory access syscall
- Does not require ptrace attach
- Detection: LSM hook or seccomp filter on the target process, kprobe on the syscall

**/proc/[pid]/mem (Linux)**:
- File-based interface to process memory
- Requires appropriate permissions (same UID or CAP_SYS_PTRACE)
- Detection: hook file_open for /proc/*/mem paths, inotify on /proc/[game_pid]/

**ptrace (Linux) / DebugActiveProcess (Windows)**:
- Full debugger attachment — read/write memory, registers, single-step
- Detection: PR_SET_PTRACER(PR_SET_PTRACER_ANY) or Yama LSM ptrace_scope, ObRegisterCallbacks on Windows

### Kernel-Mode Methods (Harder to Detect)

**MmCopyVirtualMemory (Windows)**:
- Kernel function that copies memory between processes
- Used by ReadProcessMemory internally but callable directly from a driver
- Detection: cannot be hooked due to PatchGuard; must detect the cheat driver itself

**KeStackAttachProcess / MmMapIoSpace (Windows)**:
- Attach to another process's address space from kernel, then directly access memory
- Or map physical memory into kernel virtual space
- Detection: monitor driver loads, scan for known vulnerable driver signatures

**Direct physical memory access**:
- /dev/mem (Linux, usually restricted by CONFIG_STRICT_DEVMEM)
- Custom kernel module with ioremap/phys_to_virt
- Detection: verify /dev/mem restrictions, monitor module loads

### Hardware-Level Methods (Hardest to Detect)

**DMA (Direct Memory Access) via PCIe**:
- PCILeech: FPGA-based PCIe card that reads/writes physical memory
- Screamer: commercial DMA hardware for memory forensics (abused for cheating)
- Operates below the CPU — the OS kernel cannot see DMA transactions
- Detection:
  - IOMMU/VT-d (x86) or SMMU (ARM): restrict which PCIe devices can access which memory regions
  - Verify IOMMU is enabled and configured: parse DMAR ACPI table
  - Monitor for new PCIe devices appearing (hot-plug events)
  - Timing analysis: DMA reads have different latency characteristics than CPU reads

**Hypervisor-based memory access**:
- Cheat runs a thin hypervisor below the OS
- Intercepts page table walks or uses EPT/Stage-2 to access game memory
- From the OS's perspective, memory accesses look normal
- Detection:
  - Timing-based hypervisor detection (CPUID/VMCALL timing)
  - Check if VT-x/AMD-V or ARM EL2 is already claimed (VMXON will fail if in use)
  - Measure interrupt handling latency (VM exits add measurable overhead)
  - On ARM: read HCR_EL2 if accessible, check for unexpected Stage-2 translation

## 2. Code Injection

### DLL Injection (Windows)
**CreateRemoteThread + LoadLibrary**:
- Classic approach: OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread(LoadLibraryA)
- Detection: ObRegisterCallbacks blocks the initial handle, PsSetCreateThreadNotifyRoutine detects thread creation

**NtCreateThreadEx with thread hijacking**:
- Suspend existing thread, modify its context (RIP/PC) to point to injected code
- Detection: thread context modification monitoring, stack walking to verify return addresses

**APC injection**:
- Queue APC to target thread: QueueUserAPC or NtQueueApcThread
- When thread becomes alertable, APC executes the injected code
- Detection: monitor NtQueueApcThread calls, ETW Threat Intelligence provider

**Manual mapping (reflective DLL injection)**:
- Parse PE headers, allocate memory, copy sections, resolve imports, call DllMain — all without LoadLibrary
- No entry in PEB loader lists
- Detection: scan for PE headers in non-module memory regions (VAD walk), detect RWX memory allocations

### Shared Object Injection (Linux)
**LD_PRELOAD**:
- Environment variable that forces loading a shared library before all others
- Detection: check /proc/[pid]/environ for LD_PRELOAD, verify loaded libraries against whitelist

**ptrace-based injection**:
- Attach via ptrace, inject shellcode that calls dlopen()
- Detection: restrict ptrace via Yama LSM or seccomp

**VDSO/vsyscall manipulation**:
- Replace functions in the VDSO page (mapped into every process)
- Detection: hash VDSO contents, verify against known-good

## 3. Memory Manipulation for Game State Modification

### Direct Value Modification
- Find health/ammo/position values in game memory
- Tools: Cheat Engine, GameConqueror, scanmem
- Scan for known values, modify them
- **Counter**: encrypt/obfuscate game state values (XOR with rolling key, store complements)
- **Counter**: server-side validation of game state

### Pointer Chain Following
- Navigate object hierarchies: PlayerManager -> LocalPlayer -> Health
- Requires reverse engineering of game object layouts
- **Counter**: randomize object layouts (ASLR for game objects), pointer encryption

### Function Hooking (In-Process)
**Inline hooks**:
- Overwrite first bytes of target function with JMP to cheat code
- x86: `JMP rel32` (5 bytes) or `MOV RAX, addr; JMP RAX` (12 bytes)
- ARM64: `LDR X16, [PC, #8]; BR X16; .quad addr` (12 bytes for absolute, 4 bytes for relative B)
- Detection: compare function prologues against known-good copies

**IAT/GOT hooks**:
- Modify Import Address Table (Windows) or Global Offset Table (Linux) entries
- Redirect function calls to cheat code
- Detection: verify IAT/GOT entries point within expected module address ranges

**VTable hooks**:
- Game objects using virtual functions have vtable pointers
- Cheat creates fake vtable with modified function pointers
- Detection: verify vtable pointers point to legitimate read-only data sections

**Hardware breakpoint hooks** (stealth):
- Use debug registers (DR0-DR3 on x86, DBGBVR on ARM64)
- Set breakpoint on target function, handle exception in cheat's vectored exception handler
- No code modification — undetectable by code integrity checks
- Detection: read debug registers, monitor SetThreadContext/ptrace(POKEUSER)

## 4. Rendering Exploits

### Wallhacks (ESP — Extra-Sensory Perception)
**Method 1: Depth buffer manipulation**:
- Hook Direct3D/Vulkan/OpenGL depth test
- Disable depth testing so all player models render on top of walls
- Set `D3DRS_ZENABLE = FALSE` or modify depth compare function

**Method 2: Shader replacement**:
- Replace pixel shader for player model materials
- Cheat shader ignores depth, renders in bright colors
- Detection: shader hash verification, monitor shader creation/binding calls

**Method 3: Data extraction**:
- Read enemy positions from game memory
- Render overlays using separate Direct3D/Vulkan surface or transparent window
- Detection: enumerate visible windows, check for overlay windows (WS_EX_TRANSPARENT + WS_EX_TOPMOST)

### Aimbot
**Implementation approaches**:
1. Read enemy positions from game memory
2. Calculate angle from player to nearest visible enemy
3. Either:
   a. Write aim angles directly to game memory
   b. Simulate mouse input (SendInput, mouse_event, or driver-level input injection)
   c. Use hardware input device (Arduino-based mouse emulator — "Cronus" devices)

**Detection strategies**:
- Input validation: compare raw HID input from kernel driver against processed game input
- Statistical analysis: measure aim snap speed, angular velocity consistency, target acquisition time
- Replay analysis: server-side review of player aim patterns
- Humanization detection: cheats add random noise, but the noise distribution differs from real human input

## 5. Kernel-Mode Cheat Architecture

### Typical Kernel Cheat Structure

```
[Cheat Userspace Component]
    |
    | IOCTL / shared memory
    |
[Cheat Kernel Driver]
    |
    | MmCopyVirtualMemory / KeStackAttachProcess
    |
[Game Process Memory]
```

The kernel driver provides:
- **Read/Write primitives**: bypass anti-cheat's handle protection
- **Process hiding**: unlink from EPROCESS list (ActiveProcessLinks)
- **Module hiding**: unlink from PsLoadedModuleList
- **Callback removal**: find and unregister anti-cheat's kernel callbacks

### Callback Removal Attack

Cheats locate and remove anti-cheat kernel callbacks:

```c
// Conceptual: finding ObRegisterCallbacks registration
// Walk callback list linked from ObjectType structure
POBJECT_TYPE processType = *PsProcessType;
// Undocumented: ObjectType->CallbackList contains registered callbacks
// Cheat walks this list, finds anti-cheat entries, unlinks them

// Similarly for PsSetCreateProcessNotifyRoutineEx:
// Callbacks stored in PspCreateProcessNotifyRoutine array (undocumented)
// Cheat finds the array, zeroes out the anti-cheat's entry
```

**Counter-measures**:
- Periodically verify callbacks are still registered (re-read the lists)
- Use multiple overlapping detection mechanisms (callback removal disables one, others still work)
- Heartbeat from kernel to userspace to server — if heartbeat stops, assume tampering
- Self-integrity: hash the anti-cheat driver's callback registration code

### BYOVD (Bring Your Own Vulnerable Driver) — Detailed

Attack flow:
1. Cheat includes a legitimately signed but vulnerable driver (e.g., gdrv.sys)
2. Load the vulnerable driver using normal driver loading (sc create, NtLoadDriver)
3. Exploit the vulnerability to gain arbitrary kernel read/write
4. Use kernel R/W to:
   - Disable anti-cheat callbacks
   - Read game process memory directly
   - Hide the cheat driver from enumeration
5. Optionally unload the vulnerable driver after establishing persistence

**Why it works**: the driver is validly signed, so Windows allows it to load. The vulnerability gives the cheat kernel-level access.

**Defense**:
- Maintain a blocklist of known vulnerable driver hashes
- Windows: HVCI driver blocklist (ci.dll), Microsoft-maintained
- Riot Vanguard: blocks known vulnerable drivers from loading at boot
- Monitor for any driver loads (PsSetLoadImageNotifyRoutine), compare against blocklist
- On Linux: module signature enforcement + audit log of module loads

## 6. Anti-Analysis / Anti-Debug Techniques Used by Cheats

These make reverse engineering the cheat harder:

- **VMProtect / Themida**: commercial code virtualizers — translate x86/ARM to custom bytecode
- **Timing checks**: measure execution time between points; debugger single-stepping causes massive slowdowns
- **API hooking detection**: cheats check if anti-cheat has hooked their own API calls
- **Thread hiding**: NtSetInformationThread(ThreadHideFromDebugger) — thread becomes invisible to debuggers
- **Syscall evasion**: instead of calling ntdll!NtReadVirtualMemory, directly issue SYSCALL instruction
  - Bypasses any ntdll-level hooks
  - On ARM64: directly execute SVC instruction instead of going through libc
- **Encrypted memory**: cheat code is encrypted in memory, decrypted only during execution, re-encrypted after
- **Anti-VM**: detect if running in analysis VM (CPUID checks, registry artifacts, hardware identifiers)

## 7. Network-Level Cheating (Server-Relevant)

Not directly in scope for kernel anti-cheat but context for the full picture:

- **Packet manipulation**: modify game network traffic to falsify position, damage, etc.
  - Counter: server authoritative game state, input validation, encrypted + authenticated packets
- **Lag switching**: artificially induce latency to gain advantage
  - Counter: server-side lag compensation limits, kick on sustained packet loss
- **Speed hacking**: modify game tick rate or time dilation
  - Counter: server tracks client time vs server time, reject impossible state changes
