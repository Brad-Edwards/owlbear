# Anti-Cheat vs EDR: A Technical Comparison of Parallel Universes

Anti-cheat (AC) and Endpoint Detection and Response (EDR) systems are strikingly similar in their kernel-level architecture — and yet operate under fundamentally different trust models, adversarial constraints, and design pressures. This document is a technical comparison of where they converge, where they diverge, and what each can learn from the other.

## The Core Divergence: Who Is the Adversary?

This is the single most important architectural difference, and everything else flows from it.

| | EDR | Anti-Cheat |
|---|---|---|
| **Adversary** | External attacker (malware, APT, ransomware operator) | The local user themselves |
| **User relationship** | Cooperative — user and vendor are allies against external threats | Adversarial — the user IS the threat actor |
| **Admin access assumption** | Adversary usually starts unprivileged, escalates | User already has full admin/root access from day one |
| **Physical access** | Rare (targeted attacks only) | Common (it's their own machine) |
| **Motivation** | Espionage, ransom, destruction | Competitive advantage, ego, profit (cheat selling) |

Source: [Meekolab: Understanding Kernel-Level Anticheats](https://research.meekolab.com/understanding-kernel-level-anticheats-in-online-games)

**Why this matters architecturally**: EDRs can assume a cooperative OS environment — the admin wants the EDR running. Anti-cheats cannot assume this. The user may actively try to disable, blind, or remove the anti-cheat. This means anti-cheat needs stronger self-protection and cannot rely on the user not having root.

## Shared Kernel Infrastructure

Both EDR and AC systems register the same Windows kernel callbacks. The post-PatchGuard world forced both to use Microsoft's documented callback APIs instead of direct kernel structure hooking (SSDT hooks, IDT hooks, etc.).

### Kernel Callbacks — Identical API Surface

| Callback API | EDR Use | Anti-Cheat Use |
|---|---|---|
| `PsSetCreateProcessNotifyRoutineEx` | Detect malware process creation, log process trees | Detect cheat process launch, monitor for injectors |
| `PsSetCreateThreadNotifyRoutine` | Detect remote thread injection (classic process injection) | Detect CreateRemoteThread-based DLL injection into game |
| `PsSetLoadImageNotifyRoutine` | Detect malicious DLL/driver loads | Detect cheat DLL loads, monitor driver loads for BYOVD |
| `ObRegisterCallbacks` | Monitor handle operations to detect process injection attempts | **Strip handle access rights** to prevent ReadProcessMemory on game |
| `CmRegisterCallbackEx` | Detect malicious registry modifications (persistence, config) | Detect registry tampering with AC configuration |
| `FltRegisterFilter` (Minifilter) | Detect ransomware file operations, data exfiltration | Prevent game file modification, detect cheat file drops |

Sources: [EDR Internals - Xsec](https://docs.contactit.fr/posts/evasion/edr-internals/), [WhiteFlag: From Windows Drivers to EDR](https://blog.whiteflag.io/blog/from-windows-drivers-to-a-almost-fully-working-edr/), [RealBlindingEDR](https://github.com/myzxcg/RealBlindingEDR)

**Key difference in ObRegisterCallbacks usage**: EDRs use it primarily for *monitoring* (logging who opens handles to what). Anti-cheats use it for *enforcement* (actively stripping PROCESS_VM_READ / PROCESS_VM_WRITE from handles). This reflects the real-time intervention requirement of anti-cheat vs the detect-and-respond model of EDR.

### ETW (Event Tracing for Windows)

| ETW Capability | EDR | Anti-Cheat |
|---|---|---|
| `Microsoft-Windows-Threat-Intelligence` provider | Primary telemetry source — detects cross-process memory writes, remote thread creation, context modification | Generally NOT available — requires PPL signer from Microsoft's MVI program, which ACs typically don't have |
| PowerShell / .NET ETW providers | Critical for detecting living-off-the-land attacks | Not relevant (games don't use PowerShell) |
| Kernel process/thread/image ETW | Supplementary to kernel callbacks | Supplementary to kernel callbacks |

**This is a significant sophistication gap**: EDRs from CrowdStrike, SentinelOne, Microsoft Defender, etc. have access to the Threat Intelligence ETW provider because they run as Protected Process Light (PPL) with Microsoft co-signed ELAM drivers. This gives them telemetry on `NtAllocateVirtualMemory` with executable permissions, `NtWriteVirtualMemory` (cross-process), `NtMapViewOfSection` (remote), and `NtSetContextThread` — all of which are injection indicators.

Anti-cheat vendors generally do NOT have PPL/ELAM signer status (Javelin, Vanguard, EAC, BattlEye are not PPL processes). They must detect these same operations through kernel callbacks and their own monitoring, without the privileged ETW stream.

Sources: [FluxSec: ETW Threat Intelligence](https://fluxsec.red/event-tracing-for-windows-threat-intelligence-rust-consumer), [O'Reilly: Evading EDR Ch.12](https://www.oreilly.com/library/view/evading-edr/9781098168742/xhtml/chapter12.xhtml), [HackBalak: ETW TI Provider](https://hackbalak.github.io/posts/ETW-TI-Provider/)

### Userland Hooking

Both EDR and AC hook userspace API functions, but with different targets:

**EDR userland hooks** (in ntdll.dll):
- Hook `NtCreateFile`, `NtWriteFile` — detect file-based attacks
- Hook `NtAllocateVirtualMemory`, `NtProtectVirtualMemory` — detect memory manipulation
- Hook `NtCreateThreadEx` — detect remote thread creation
- Hook `NtWriteVirtualMemory` — detect cross-process writes
- Implementation: overwrite function prologue with `JMP` to EDR monitoring DLL
- Detection: compare ntdll function prologues against on-disk copy (bytes should start with `4C 8B D1 B8` for Nt* functions)

**Anti-cheat userland hooks** (in game process):
- Hook `NtQueryVirtualMemory` — detect memory scanners (Cheat Engine)
- Hook `NtReadVirtualMemory` — detect debugger memory reads
- Hook `NtGetContextThread` / `NtSetContextThread` — detect debug register manipulation
- Hook rendering APIs (D3D, Vulkan) — detect overlay/wallhack cheats
- BattlEye injects position-independent shellcode (not a DLL) to avoid detection via module enumeration

**Shared vulnerability**: both EDR and AC userland hooks are bypassable by:
1. Direct syscalls (skip ntdll entirely, issue `SYSCALL` instruction directly)
2. Loading a clean copy of ntdll from disk and calling through it
3. Unhooking (reading original bytes from disk, restoring function prologues)

Sources: [MalwareTech: Bypassing User Mode EDR Hooks](https://malwaretech.com/2023/12/an-introduction-to-bypassing-user-mode-edr-hooks.html), [MDSec: FireWalker](https://www.mdsec.co.uk/2020/08/firewalker-a-new-approach-to-generically-bypass-user-space-edr-hooking/), [s3cur3th1ssh1t: EDR Bypass Methods](https://s3cur3th1ssh1t.github.io/A-tale-of-EDR-bypass-methods/)

## Boot-Time Loading: ELAM vs Anti-Cheat Boot Drivers

### EDR: Early Launch Anti-Malware (ELAM)

Microsoft provides the ELAM framework specifically for security products:
- ELAM driver loads before all other third-party boot-start drivers
- Must be co-signed by Microsoft (requires joining the MVI program)
- Enables the security product to classify other boot-start drivers as Good, Bad, or Unknown
- Bad drivers can be prevented from loading
- Grants access to PPL protection and the Threat Intelligence ETW provider

CrowdStrike Falcon, Microsoft Defender, SentinelOne, and other major EDRs use ELAM. This is a **Microsoft-blessed** early boot position with formal APIs and protections.

Source: [Microsoft: Overview of ELAM](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/early-launch-antimalware), [Immersive Labs: CrowdStrike ELAM](https://www.immersivelabs.com/resources/blog/unforseen-consequences-the-impact-of-faulty-edr-and-elam-drivers)

### Anti-Cheat: Boot-Start Without ELAM

Vanguard and Javelin load at boot time but do NOT use ELAM:
- They register as standard boot-start kernel drivers
- They enforce Secure Boot to ensure the boot chain is clean
- They block known-vulnerable drivers from coexisting (their own blocklist, not ELAM's classification)
- They do NOT get PPL protection or TI ETW access

**Net effect**: EDRs get a formalized, Microsoft-supported early boot position with privileged telemetry access. Anti-cheats achieve a similar boot-time trust anchor through a more ad-hoc approach (Secure Boot enforcement + their own driver blocklist), but without the privileged APIs that come with ELAM membership.

## Self-Protection: PPL vs Roll-Your-Own

### EDR Self-Protection

Top EDRs run as **Protected Process Light (PPL)** with signer level `PsProtectedSignerAntimalware-Light`:
- Kernel enforces that no process (even SYSTEM) can open a handle to the PPL process with write/terminate access
- PPL process memory cannot be read or written by non-PPL processes
- PPL cannot be terminated via Task Manager or `taskkill`
- Registry keys and files used by the EDR are protected by kernel-mode tamper protection
- Service cannot be stopped, disabled, or restarted without EDR authorization

This is backed by **hardware** — PPL enforcement is in the Windows kernel, protected by PatchGuard, and further backed by HVCI/VBS on modern systems.

Source: [FluxSec: Creating a PPL](https://fluxsec.red/creating-a-ppl-protected-process-light-in-rust-windows), [RedOps: Tampering EDRs](https://redops.at/en/blog/a-story-about-tampering-edrs)

### Anti-Cheat Self-Protection

Anti-cheats must protect themselves WITHOUT PPL status:
- `ObRegisterCallbacks` on their own process/thread objects to strip handle access
- Self-hashing of driver `.text` section to detect code modification
- Watchdog threads/processes — if the AC dies, the game dies
- Heartbeat to remote server — if heartbeats stop, server assumes tampering
- Encrypted IPC between AC components
- Integrity verification of AC's own kernel callbacks (detect callback removal attacks)

**This is a real sophistication difference**: EDRs get OS-enforced tamper protection for free via PPL. Anti-cheats must build their own tamper protection from scratch, which is inherently weaker because it operates at the same privilege level as the attacker (Ring 0).

One researcher noted that EAC's integrity checks were "significantly better than listed security solutions" in some areas — specifically dynamic kernel-level text section protection — suggesting anti-cheats have been forced to innovate in self-protection more aggressively than EDRs that can lean on PPL.

Source: [OverlayHack: EDR Bypass Evasion](https://overlayhack.com/edr-bypass-evasion)

## Detection Philosophy

### EDR: Detect and Respond (After the Fact)

EDR detection pipeline:
```
Telemetry Collection (callbacks, ETW, minifilter, hooks)
  -> Event Correlation (process trees, behavior chains)
    -> ML/Behavioral Analysis (cloud-based models)
      -> Alert Generation (SOC analyst reviews)
        -> Response (isolate, quarantine, remediate)
```

- Can tolerate latency — an alert 30 seconds after an event is still useful
- False positives are manageable — SOC analyst triages
- Post-breach forensics is a core capability (timeline reconstruction)
- Cloud-based ML models process telemetry centrally
- Emphasis on **visibility** — see everything, decide later

### Anti-Cheat: Prevent in Real-Time (Before Impact)

Anti-cheat detection pipeline:
```
Kernel Monitoring (callbacks, memory scanning, integrity checks)
  -> In-Process Verification (code integrity, hook detection)
    -> Real-Time Decision (allow/block/kill)
      -> Server-Side Analysis (telemetry, ML, behavioral stats)
        -> Enforcement (ban, session kill)
```

- Must prevent cheating **before it impacts gameplay** — a detection 30 seconds later means 30 seconds of unfair matches
- False positives are catastrophic — banning a legitimate player destroys trust
- Real-time intervention: immediate process termination, session invalidation, handle stripping
- Memory scanning is active and continuous (not just event-triggered)
- Emphasis on **prevention** — stop the cheat from functioning at all

Source: [Meekolab: Understanding Kernel-Level Anticheats](https://research.meekolab.com/understanding-kernel-level-anticheats-in-online-games), [EA Progress Report](https://www.ea.com/security/news/anticheat-progress-report)

## Memory Scanning: Different Approaches to the Same Problem

### EDR Memory Scanning

- **Event-triggered**: scan memory only when a suspicious event occurs (e.g., remote thread created, executable memory allocated)
- **Yara rules**: match known malware signatures in memory
- **Selective**: full memory scanning is too resource-intensive; scan specific regions flagged by behavioral triggers
- **Focus**: injected shellcode, reflectively loaded DLLs, packed/unpacked malware

Source: [r-tec: Process Injection Avoiding Memory Scans](https://www.r-tec.net/r-tec-blog-process-injection-avoiding-kernel-triggered-memory-scans.html)

### Anti-Cheat Memory Scanning

- **Continuous**: periodically scan entire game process memory (not just on events)
- **Byte pattern signatures**: match known cheat binary fragments with wildcard support
- **PE header detection**: scan all committed memory for MZ/PE headers — finds manually mapped modules
- **VAD walking**: traverse Virtual Address Descriptor tree to find hidden modules (bypasses PEB unlinking)
- **Code integrity**: hash game `.text` sections and compare against known-good values
- **Hook detection**: compare function prologues against on-disk originals
- **Focus**: injected cheat DLLs, code patches, modified function pointers

**Key difference**: anti-cheat scans proactively and continuously because the cheat is persistent (it runs for the duration of the game session). EDRs scan reactively because malware execution is often a brief event.

Source: [Guided Hacking: Memory Scan Bypass](https://guidedhacking.com/threads/how-to-bypass-memory-scan-detection-for-anti-cheat.20635/)

## Behavioral / ML Detection

### EDR Behavioral Models

- Process tree anomaly detection (e.g., Word spawning PowerShell spawning cmd)
- Network behavior clustering (beaconing detection, C2 pattern recognition)
- File access pattern analysis (ransomware: rapid sequential file opens + writes + renames)
- MITRE ATT&CK technique mapping
- Trained on **billions of events** from global sensor fleet (CrowdStrike: 2T+ events/week)
- Cloud-scale inference — raw telemetry sent to cloud, ML runs server-side

Source: [Palo Alto: EDR ML](https://www.paloaltonetworks.com/cyberpedia/how-edr-leverages-machine-learning)

### Anti-Cheat Behavioral Models

- Aim pattern analysis: angular velocity, snap speed, target acquisition time
- Input timing distributions: human input follows specific statistical distributions; bots/aimbots differ
- Movement pattern analysis: speedhacks, teleportation, impossible position changes
- Reaction time analysis: unnaturally consistent reaction times indicate aimbot
- Kill/death statistical anomalies: headshot percentages, kill distances, weapon accuracy
- Trained on **gameplay telemetry** — per-match player behavior data
- Mix of client-side heuristics + server-side statistical analysis

Source: [ResearchGate: Behavioral Cheating Detection in FPS](https://www.researchgate.net/publication/261497438_Behavioral-based_cheating_detection_in_online_first_person_shooters_using_machine_learning_techniques)

**Sophistication comparison**: EDR behavioral models are more mature, operating at larger scale with more diverse signal types. Anti-cheat behavioral models are more domain-specific and have a harder false-positive constraint (wrongly banning a player is worse than a false EDR alert that a SOC analyst dismisses).

## The BYOVD Crossover: Where Anti-Cheat Drivers Became Weapons Against EDR

This is perhaps the most ironic convergence point: **vulnerable anti-cheat drivers are being weaponized by ransomware operators to kill EDR products**.

### Notable Cases

| Driver | Origin | CVE | Used By | What It Killed |
|--------|--------|-----|---------|----------------|
| `GameDriverx64.sys` | Gaming anti-cheat | CVE-2025-61155 | Interlock ransomware ("Hotta Killer") | Fortinet, various EDR/AV |
| `gdrv.sys` | GIGABYTE tools (not AC, but gaming ecosystem) | CVE-2018-19320 | RobbinHood, BlackByte ransomware | Multiple EDRs |
| `NSecKrnl.sys` | NsecSoft security | N/A | Reynolds ransomware | CrowdStrike, Cortex XDR, Sophos, Symantec |
| `capcom.sys` | Capcom anti-cheat | N/A | Multiple cheat tools, red team tools | Various security products |
| Baidu AV driver | Baidu Antivirus | N/A | DeadLock ransomware | EDR defenses |

The attack flow:
1. Ransomware drops a legitimately signed (but vulnerable) driver
2. Exploits the driver's vulnerability to gain arbitrary kernel R/W
3. Uses kernel access to find and remove EDR kernel callbacks
4. Terminates EDR processes (now unprotected without callbacks)
5. Proceeds with ransomware payload with no endpoint security watching

Sources: [The Hacker News: Reynolds BYOVD](https://thehackernews.com/2026/02/reynolds-ransomware-embeds-byovd-driver.html), [CyberSecurityNews: Interlock Ransomware](https://cybersecuritynews.com/interlock-ransomware-actors-new-tool-exploiting-gaming-anti-cheat-driver-0-day/), [Talos: DeadLock BYOVD Loader](https://blog.talosintelligence.com/byovd-loader-deadlock-ransomware/), [ThreatIntelReport: BYOVD in 2026](https://www.threatintelreport.com/2026/02/21/articles/byovd-in-2026-the-signed-driver-loophole-powering-edr-bypass-at-scale/)

**The irony**: gaming anti-cheat drivers — built to protect games from cheaters — have become the preferred weapon for ransomware operators to disable enterprise security products. Both the anti-cheat and EDR ecosystems suffer from the same fundamental Windows driver trust model weakness: any signed driver with a vulnerability becomes a skeleton key to kernel access.

### BYOVD Origin Story: The Cheat Community Got There First

BYOVD is often discussed as a "rising threat" in enterprise security, but it was a **mature, commoditized technique in the game cheat community 3-4 years before the first ransomware group adopted it**. The knowledge transfer was one-directional: cheat devs to malware operators.

**Cheat community timeline:**
- **Sept 2016**: `capcom.sys` exploit disclosed by @TheWack0lian. Capcom's anti-cheat driver had an IOCTL that literally executed a user-supplied function pointer in Ring 0 with SMEP disabled. The cheat community was using it to bypass EAC/BattlEye within weeks. ([ExploitCapcom on GitHub](https://github.com/tandasat/ExploitCapcom), [FuzzySecurity: Capcom Rootkit POC](https://fuzzysecurity.com/tutorials/28.html))
- **2017-2018**: `gdrv.sys` (GIGABYTE, CVE-2018-19320), `RTCore64.sys` (MSI), `dbutil_2_3.sys` (Dell) all actively exploited by cheat developers for arbitrary kernel R/W to bypass anti-cheat kernel callbacks.
- **2019**: `kdmapper` released publicly — exploited Intel's `iqvw64e.sys` (CVE-2015-2291) to manually map unsigned cheat drivers into kernel memory. This massively lowered the barrier; any cheat developer could load kernel drivers past anti-cheat. UnknownCheats and Guided Hacking forums had extensive tutorials, driver vulnerability lists, and production-ready tooling. ([kdmapper on GitHub](https://github.com/TheCruZ/kdmapper), [Guided Hacking: Vulnerable Kernel Drivers](https://guidedhacking.com/threads/vulnerable-kernel-drivers-for-exploitation.15979/))

**Ransomware adoption timeline (years later):**
- **2019**: RobbinHood — first ransomware using BYOVD, with `gdrv.sys`. Same driver cheaters had used for 1+ year. ([Rapid7: Driver-Based Attacks](https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/))
- **2021**: Lazarus APT used `dbutil_2_3.sys` (Dell). ([ESET Research](https://www.eset.com/us/about/newsroom/research/esets-research-into-bring-your-own-vulnerable-driver-details-attacks-on-drivers-in-windows-core/))
- **2022**: BlackByte ransomware used `RTCore64.sys` (MSI) — same driver cheat community had exploited for years.
- **2023**: SpyBoy's "Terminator" — commercialized BYOVD EDR killer, sold for $3000. Directly borrowed cheat community techniques.
- **2024-2025**: ~25% of ransomware attacks incorporate BYOVD. Fully commoditized. ([Picus Security](https://www.picussecurity.com/resource/blog/what-are-bring-your-own-vulnerable-driver-byovd-attacks))
- **2025-2026**: Anti-cheat drivers themselves (`GameDriverx64.sys`, CVE-2025-61155) weaponized against EDRs. ([CyberSecurityNews: Interlock Ransomware](https://cybersecuritynews.com/interlock-ransomware-actors-new-tool-exploiting-gaming-anti-cheat-driver-0-day/))

**What this means**: The anti-cheat industry was the canary in the coal mine for BYOVD. AC vendors developed defenses (driver blocklisting, Secure Boot enforcement, HVCI requirements, vulnerable driver databases) years before the enterprise security world faced the same threat at scale. Vanguard was blocking vulnerable drivers at boot before most EDR vendors had BYOVD on their radar. The enterprise security industry effectively had a multi-year advance warning from the gaming security ecosystem and was slow to act on it.

This is a strong interview talking point: understanding that threat techniques often debut in the gaming/cheat ecosystem before migrating to APT/ransomware demonstrates cross-domain threat intelligence awareness.

### Shared Defense: Driver Blocklisting

Both EDR and AC now maintain driver blocklists:
- **Microsoft**: maintains the HVCI vulnerable driver blocklist in `ci.dll`
- **CrowdStrike**: blocks known BYOVD drivers at sensor level
- **Javelin**: blocks vulnerable/unsigned/HVCI-incompatible drivers, refuses game launch
- **Vanguard**: blocks known-vulnerable drivers from loading at boot

Source: [CrowdStrike: Falcon Prevents Vulnerable Driver Attacks](https://www.crowdstrike.com/en-us/blog/falcon-prevents-vulnerable-driver-attacks-real-world-intrusion/), [Halcyon: Blocking BYOVD](https://www.halcyon.ai/blog/blocking-byovd-techniques-to-prevent-av-edr-xdr-bypasses)

## Kernel Crash Risk: The CrowdStrike Lesson

Both EDR and AC drivers share the same catastrophic failure mode: a bug in a Ring 0 driver crashes the entire system.

**CrowdStrike outage (July 19, 2024)**:
- Faulty definition file update caused an out-of-bounds memory read in kernel mode
- Result: BSOD on ~8.5 million Windows machines globally
- Root cause: insufficient input validation in the content interpreter, combined with the definition file not being tested against the specific template type
- The ELAM boot-start position meant affected machines were trapped in boot loops

**Anti-cheat equivalents**:
- Anti-cheat driver bugs regularly cause BSODs on individual gaming PCs
- Vanguard has caused BSOD issues with specific hardware/driver combinations
- Javelin incompatibilities with third-party drivers can prevent Windows boot

**Same root problem**: both EDR and AC execute untrusted data (definition files, signature updates, configuration) in kernel context. The CrowdStrike incident demonstrated that even the most sophisticated Ring 0 security product can bring down the system if kernel code doesn't validate its inputs rigorously.

Source: [CrowdStrike Root Cause Analysis](https://www.securityweek.com/crowdstrike-releases-root-cause-analysis-of-falcon-sensor-bsod-crash/), [Immersive Labs: CrowdStrike ELAM Impact](https://www.immersivelabs.com/resources/blog/unforseen-consequences-the-impact-of-faulty-edr-and-elam-drivers)

## Evasion Techniques: The Shared Attack Surface

Both EDR and AC are vulnerable to the same kernel-level evasion techniques. Tools built to bypass one often work against the other.

### Callback Removal

Tools like [RealBlindingEDR](https://github.com/myzxcg/RealBlindingEDR) and [EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast) remove kernel callbacks by:
1. Loading a vulnerable driver (BYOVD) to get kernel R/W
2. Locating the callback arrays in kernel memory:
   - `PspCreateProcessNotifyRoutine`
   - `PspCreateThreadNotifyRoutine`
   - `PspLoadImageNotifyRoutine`
3. Zeroing out the callback entries
4. Result: the security product's kernel driver is still running but receives no events

**Applies to both EDR and AC identically** — the callback arrays are the same regardless of who registered them.

Source: [RealBlindingEDR](https://github.com/myzxcg/RealBlindingEDR), [EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast)

### Direct Syscalls

Both EDR userland hooks and AC userland hooks are bypassed by issuing system calls directly:
- Read the syscall number from ntdll's `Nt*` function stubs
- Execute `SYSCALL` instruction directly with the number in EAX
- Skips the hooked ntdll function entirely
- Tools: SysWhispers, HellsGate, HalosGate

Source: [ired.team: Detecting Hooked Syscalls](https://www.ired.team/offensive-security/defense-evasion/detecting-hooked-syscall-functions)

### ETW Blinding

Patching `EtwEventWrite` in ntdll to return immediately:
- Disables all userspace ETW telemetry
- Affects both EDR and AC ETW consumers
- Kernel-level ETW (TI provider) is not affected by this technique

### Hardware Breakpoint Hooking

Using debug registers (DR0-DR3) for stealthy hooks that modify no code:
- Used by cheats to hook game functions without tripping code integrity checks
- Used by red team tools to hook ntdll functions without tripping EDR integrity checks
- The Blindside technique specifically targets EDR evasion via hardware breakpoints

Source: [Cymulate: Blindside EDR Evasion](https://cymulate.com/blog/blindside-a-new-technique-for-edr-evasion-with-hardware-breakpoints/)

## The EDR Killer Evolution — A Cautionary Timeline

This timeline shows how EDR evasion tools have escalated, paralleling cheat tool evolution:

```
2022: AuKill, EDRSandblast — in-memory attacks, early BYOVD
2022: ProcBurner — privileged process injection
2023: Terminator — kernel-level EDR blinding ($3000 commercial tool)
2024: EDRKillShifter — legitimate utility abuse
2024: MS4Killer — targeted Microsoft Defender, bypassed cloud telemetry
2025: Defendnot — evaded runtime attestation AND kernel integrity checks
2026: BYOVD is now commodity — embedded directly in ransomware payloads
```

Source: [CSA: EDR Killers](https://cloudsecurityalliance.org/blog/2025/09/15/edr-killers-how-modern-attacks-are-outpacing-traditional-defenses), [ThreatIntelReport: EDR Killers in 2026](https://www.threatintelreport.com/2026/02/21/articles/edr-killers-in-2026-the-most-common-ways-attackers-neutralize-endpoint-security-and-how-to-stop-them/)

## Summary: Sophistication Comparison

| Dimension | EDR Advantage | AC Advantage | Verdict |
|-----------|--------------|--------------|---------|
| Privileged telemetry (ETW TI) | PPL + ELAM gives exclusive access | No access to TI provider | **EDR wins** |
| Self-protection | PPL enforcement by OS kernel | Must build own tamper protection | **EDR wins** |
| Boot-time trust | ELAM: Microsoft-blessed framework | Ad-hoc boot driver + Secure Boot enforcement | **EDR slightly ahead** |
| Real-time prevention | Detect-and-respond model, latency acceptable | Must prevent before impact, sub-second decisions | **AC more demanding** |
| Memory scanning depth | Event-triggered, selective | Continuous, comprehensive, includes game-specific integrity | **AC more thorough** |
| Code integrity checking | Basic process/module validation | Deep: function prologue verification, hook detection, VAD walking | **AC more thorough** |
| Adversary privilege level | Usually starts unprivileged | Adversary has root/admin from start | **AC harder problem** |
| Behavioral ML scale | Billions of events, cloud-scale inference | Per-game models, more constrained | **EDR more mature** |
| False positive tolerance | Manageable (SOC triages) | Catastrophic (wrongful ban destroys trust) | **AC higher bar** |
| BYOVD defense | Driver blocklists, some HVCI enforcement | Active driver blocklisting + Secure Boot mandate | **Roughly equal** |
| Network visibility | WFP integration, DNS monitoring, connection tracking | Minimal (game-server heartbeat) | **EDR wins** |
| Cross-platform | Windows, macOS, Linux agents | Primarily Windows, expanding to ARM64/Linux | **EDR more mature** |

## Convergence Trends

1. **Anti-cheat is becoming more EDR-like**: Javelin's ML/AI team, behavioral analysis, cloud telemetry — these are EDR capabilities being adopted by AC.

2. **EDR is learning from anti-cheat**: BYOVD defense, driver blocklisting, boot-time trust anchors — these were AC problems first (cheat drivers) that became EDR problems (ransomware BYOVD).

3. **Shared adversary tooling**: the same tools (EDRSandblast, RealBlindingEDR, BYOVD exploits) work against both. The offensive security community doesn't distinguish — a kernel callback is a kernel callback.

4. **The kernel trust problem is unsolved for both**: as the CSA report states, "The kernel has insufficient protection for the highest privileged area, where everything assumes the kernel can be trusted." Both EDR and AC suffer from this fundamental architectural limitation.

5. **ARM64 may reset the playing field**: PAC, MTE, BTI provide hardware-level protections that don't exist on x86. Both EDR and AC on ARM64 can leverage these — but neither has production implementations yet. This is where our Owlbear prototype can explore uncharted territory.

## Relevance to Owlbear

For our ARM64 anti-cheat prototype, the EDR comparison reveals:

1. **We won't have PPL/ELAM** — so we must build robust self-protection (like production ACs do)
2. **We won't have TI ETW** — so we must use kernel callbacks and eBPF (on Linux) for equivalent telemetry
3. **Our real-time prevention requirement** is harder than EDR's detect-and-respond model
4. **ARM64 hardware features** (PAC, MTE, BTI) give us protections that no x86 EDR or AC has yet deployed at scale
5. **The BYOVD lesson** applies to us — our own driver could be weaponized if it has vulnerabilities, so secure coding in our kernel module is critical
6. **Behavioral detection** should complement signature detection — EDR's ML maturity shows the value of this investment
