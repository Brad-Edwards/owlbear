# EA Javelin Anticheat: History, Architecture, and Technical Deep Dive

## Origins and Evolution

EA's anti-cheat journey followed a clear progression from third-party reliance to fully in-house kernel-mode development:

### Pre-Javelin Era
- **PunkBuster (Even Balance)**: third-party userspace anti-cheat used in Battlefield 2, 3, 4, and many other EA titles. Server-side screenshot capture + client-side memory scanning. Widely bypassed — essentially the "PB era" of anti-cheat that the industry has since moved past. [PCGamingWiki: Anti-cheat middleware](https://www.pcgamingwiki.com/wiki/Anti-cheat_middleware)
- **FairFight (GameBlocks)**: server-side statistical analysis — no client-side component at all. Used in Battlefield 1, Battlefield V, and other titles. Proprietary rule engine evaluated gameplay actions for statistical anomalies (e.g., headshot rates, kill distances). No kernel access, no driver. Strength: unbypassable client-side (nothing to bypass). Weakness: could only catch cheaters after they'd already impacted matches, reactive not preventive. [PCGamingWiki: Anti-cheat middleware](https://www.pcgamingwiki.com/wiki/Anti-cheat_middleware)
- **Easy Anti-Cheat (EAC)**: third-party kernel-mode AC (Epic-owned). Used in Apex Legends and other EA titles before Javelin. Gave EA familiarity with kernel-mode AC but without proprietary control over privacy, detection logic, or update cadence.

### Javelin Timeline
| Date | Event | Source |
|------|-------|--------|
| Sept 2022 | Launched as "EA Anti-Cheat" (EAAC) with FIFA 23 — first EA in-house kernel-mode AC | [EA Deep Dive](https://www.ea.com/security/news/eaac-deep-dive) |
| 2022-2024 | Expanded to EA SPORTS FC, Madden NFL, F1, EA SPORTS WRC, Plants vs. Zombies | [EA Progress Report](https://www.ea.com/security/news/anticheat-progress-report) |
| 2025 | Rebranded from "EA Anti-Cheat" to "EA Javelin Anticheat" — name chosen to convey "defense, strength, and agility" | [EA Introduction](https://www.ea.com/news/introducing-ea-javelin-anticheat) |
| Aug 2025 | Battlefield 6 Open Beta — 1.2M+ cheat attempts blocked, MIR dropped from 7% to 2% over beta period | [EA BF6 Season 1 Update](https://www.ea.com/en/games/battlefield/battlefield-6/news/battlefield-6-anticheat-update-season-1) |
| Oct 2025 | BF6 launch — 367K cheat attempts blocked on launch weekend alone | [EA BF6 Season 1 Update](https://www.ea.com/en/games/battlefield/battlefield-6/news/battlefield-6-anticheat-update-season-1) |
| Jan 2026 | 384,918 cheat attempts blocked in one month; tracking 224 cheat programs/vendors, 94.64% disrupted | [EA BF6 January Metrics](https://www.ea.com/games/battlefield/battlefield-6/news/battlefield-6-anticheat-metrics-january) |
| Mar 2026 | Now active in 14 EA titles, 33M+ cheat attempts blocked across 2.2B sessions since 2022 launch | [EA Progress Report](https://www.ea.com/security/news/anticheat-progress-report) |
| Mar 2026 | Job listing posted for "Senior Anti-Cheat Engineer, ARM64" — native ARM64 Windows kernel driver development | [Tom's Hardware](https://www.tomshardware.com/video-games/pc-gaming/eas-javelin-anti-cheat-is-coming-to-arm-based-systems-soon-new-job-listing-for-windows-on-arm-driver-anticipates-nvidia-n1-n1x-debut-and-pivotal-shift-in-pc-gaming), [VideoCardz](https://videocardz.com/newz/ea-job-listing-points-to-arm64-windows-driver-for-ea-javelin-anticheat) |

## Where Javelin Sits: Ring 0, Not Ring -1

Javelin operates at **Ring 0 (kernel mode)** on Windows. It does not ship its own hypervisor and does not operate at Ring -1.

However, it **leverages Ring -1 platform features** when available:
- Requires Secure Boot (verified boot chain)
- Requires TPM 2.0
- Requires HVCI-capable and VBS-capable hardware
- Uses these platform hypervisor protections to prevent unsigned kernel code execution and detect boot-time tampering

This is the same posture as Vanguard and BattlEye — they are Ring 0 drivers that benefit from the Windows hypervisor's Ring -1 enforcement, but they don't deploy their own hypervisor. The distinction matters because Ring -1 (hypervisor) operation would mean Javelin could survive a compromised OS kernel, which it cannot.

Sources: [EA BF6 Secure Boot Info](https://www.ea.com/games/battlefield/battlefield-6/news/secure-boot-information), [Windows Central](https://www.windowscentral.com/gaming/battlefield-6-says-its-kernel-level-anticheat-ea-javelin-has-been-a-huge-success)

## Architecture

### Privilege and Boot Model

Javelin loads at **boot time** with Windows (like Vanguard, unlike EAC which loads at game launch). This means:
1. Javelin establishes a trust anchor before any cheat driver can load
2. It can monitor driver loads from the earliest point possible
3. Cheats attempting to hook into memory or GPU drivers before game launch are still visible to Javelin

The boot-time loading + Secure Boot requirement creates a verified chain:
```
UEFI Firmware (Secure Boot verifies bootloader)
  -> Windows Boot Manager (verifies kernel)
    -> Windows Kernel + Hypervisor (VBS/HVCI)
      -> Javelin kernel driver (loaded early, verified by Secure Boot chain)
        -> Game process (protected by Javelin)
```

Source: [Built to Frag](https://builttofrag.com/battlefield-6-javelin-anti-cheat/)

### System Requirements Enforced

Javelin enforces these as hard prerequisites — the game will not launch without them:

| Requirement | Purpose |
|------------|---------|
| UEFI Secure Boot | Prevents unsigned bootloaders/drivers from loading before Javelin |
| TPM 2.0 | Hardware root of trust, platform integrity attestation |
| HVCI capable | Hypervisor prevents unsigned code execution in kernel mode |
| VBS capable | Isolated virtual environment for security-critical kernel operations |
| Windows 10/11 | Minimum OS version for required security features |

During BF6 Open Beta, Secure Boot adoption among players jumped from **62.5% to 92.5%** as players enabled it to play. Current adoption: **98.5%** of players can activate Secure Boot.

Source: [EA BF6 Season 1 Update](https://www.ea.com/en/games/battlefield/battlefield-6/news/battlefield-6-anticheat-update-season-1), [EA Secure Boot Info](https://www.ea.com/games/battlefield/battlefield-6/news/secure-boot-information)

### Attack Vectors Javelin Targets

From EA's official Secure Boot documentation, Javelin specifically defends against:

1. **Kernel-level cheats and rootkits** — drivers that operate at Ring 0 to hide cheat activity
2. **Memory manipulation and injection** — runtime code modification of game process
3. **Spoofing and hardware ID manipulation** — falsifying hardware identifiers to evade bans
4. **Virtual machines and emulation** — running the game in a VM to isolate cheat tools from detection
5. **Anti-cheat system tampering** — attempts to disable or modify Javelin itself

Source: [EA Secure Boot Info](https://www.ea.com/games/battlefield/battlefield-6/news/secure-boot-information)

### Driver Blocklisting

Javelin maintains a **deny list** of drivers and software that it considers security risks. If a deny-listed driver is loaded on the system, Javelin **refuses to let the game launch**.

Blocked categories include:
- **Unsigned or expired drivers** — cannot verify provenance
- **Known-vulnerable drivers** — BYOVD prevention (drivers with known arbitrary read/write primitives)
- **HVCI-incompatible drivers** — drivers that cannot coexist with hypervisor-enforced code integrity
- **System inspection tools with kernel drivers** — System Informer (Process Hacker successor) is blocked when its kernel driver (`kprocesshacker.sys` / `systeminformer.sys`) is enabled, because these provide the same read/write primitives a cheat would use
- **Input remapping software with virtual device drivers** — e.g., ReWASD was blocked when it adopted methods of registering virtual devices that could bypass anti-cheat input validation

Sources: [System Informer Issue #2647](https://github.com/winsiderss/systeminformer/issues/2647), [EA Forums](https://forums.ea.com/discussions/ea-forums-general-discussion-en/ea-javelin-anticheat--recent-software-blocks/12218073), [EA Help](https://help.ea.com/en/articles/platforms/pc-ea-anticheat/)

### Detection Architecture

EA describes a **layered defense strategy** with four main components:

```
1. Javelin kernel driver    — kernel-mode detection and prevention
2. Game client integration  — in-process integrity verification
3. Server-side detection    — statistical analysis and behavioral signals
4. Additional undisclosed   — EA deliberately does not enumerate all layers
```

Within the kernel driver, detection targets two cheat categories:

**Internal cheats** (inject into game process):
- Code injection detection (DLL injection, manual mapping, shellcode)
- Game memory integrity verification
- Hook detection (IAT/EAT, inline, vtable)
- Detection of unauthorized memory modifications to game state

**External cheats** (operate outside game process):
- Cross-process memory access monitoring (ReadProcessMemory, etc.)
- Pixel-bot detection (screen reading for aimbot/ESP)
- Kernel-mode driver monitoring (detect cheat drivers)
- Input injection detection (synthetic input from external processes)

The system uses "hundreds of specific detections" (signature-based) plus "generic telemetry signals" (behavioral/heuristic).

Source: [EA Progress Report](https://www.ea.com/security/news/anticheat-progress-report)

### LSASS Monitoring Controversy

Community reports surfaced showing Windows Defender alerts when Javelin accessed `lsass.exe` (Local Security Authority Subsystem Service). EA has not officially commented on this. Community security analysis suggests this is legitimate anti-cheat behavior: cheats sometimes exploit LSASS to gain kernel access or escalate privileges (e.g., CVE-2024-22830), so monitoring LSASS access patterns is a reasonable defensive measure. The monitoring does not indicate credential harvesting — it indicates Javelin is watching for other processes attempting to abuse LSASS.

Source: [Steam Community Discussion](https://steamcommunity.com/app/2807960/discussions/0/664963445168452586/)

## Team Structure

EA's anti-cheat organization has three pillars:

| Pillar | Role | Expertise |
|--------|------|-----------|
| **Engineering** | Build and maintain Javelin's kernel driver, userspace components, and infrastructure | Vulnerability research, kernel development, game development |
| **Operations** | Investigate cheating, issue bans, reverse engineer cheat tools, provide feedback for detection improvements | Reverse engineering, threat intelligence, enforcement |
| **Data Science** | Build ML/AI models for cheat detection, measure effectiveness, enable scaling across game genres | Machine learning, statistical analysis, data engineering |

EA states the team is "customizable and offers a unique and modified approach for Battlefield and other EA FPS games" — implying per-title tuning of detection logic, not a one-size-fits-all deployment.

Source: [EA Progress Report](https://www.ea.com/security/news/anticheat-progress-report)

## Operational Model

### Runtime Behavior
- Javelin kernel driver loads at **Windows boot time**
- Full monitoring activates only when a protected game is running
- All AC processes shut down when the game closes
- Auto-uninstalls if all protected EA games are removed from the system
- Can be manually uninstalled at any time (but required for protected games)

### Privacy Posture (EA's Claims)
- Collects only information "necessary for anticheat purposes"
- Does not access browsing history, unrelated applications, or non-game processes
- Uses **cryptographic hashing** to create unique identifiers, then discards original data
- Independently audited by third-party security and privacy firms
- However, privacy advocates note EA provides insufficient specifics about what exactly is collected, how long it's retained, and how GDPR compliance is ensured

Source: [EA Deep Dive](https://www.ea.com/security/news/eaac-deep-dive), [Built to Frag](https://builttofrag.com/battlefield-6-javelin-anti-cheat/)

## Measured Effectiveness

### Battlefield 6 Metrics

| Metric | Value | Source |
|--------|-------|--------|
| Open Beta cheat attempts blocked | 1.2M+ | [EA BF6 Season 1](https://www.ea.com/en/games/battlefield/battlefield-6/news/battlefield-6-anticheat-update-season-1) |
| Open Beta MIR progression | 7% -> 2% (Aug 7-17, 2025) | [EA BF6 Season 1](https://www.ea.com/en/games/battlefield/battlefield-6/news/battlefield-6-anticheat-update-season-1) |
| Launch weekend blocks | 367,000+ | [EA BF6 Season 1](https://www.ea.com/en/games/battlefield/battlefield-6/news/battlefield-6-anticheat-update-season-1) |
| Cumulative blocks (to Season 1 report) | 2.39M | [EA BF6 Season 1](https://www.ea.com/en/games/battlefield/battlefield-6/news/battlefield-6-anticheat-update-season-1) |
| January 2026 blocks | 384,918 | [EA BF6 January Metrics](https://www.ea.com/games/battlefield/battlefield-6/news/battlefield-6-anticheat-metrics-january) |
| Cheat programs tracked | 224 | [EA BF6 January Metrics](https://www.ea.com/games/battlefield/battlefield-6/news/battlefield-6-anticheat-metrics-january) |
| Cheat programs disrupted | 212 (94.64%) | [EA BF6 January Metrics](https://www.ea.com/games/battlefield/battlefield-6/news/battlefield-6-anticheat-metrics-january) |
| Cheat sellers reporting failures/takedowns | 183/190 (96.3%) at Season 1 | [EA BF6 Season 1](https://www.ea.com/en/games/battlefield/battlefield-6/news/battlefield-6-anticheat-update-season-1) |
| Ban accuracy rate | >99% | [EA Progress Report](https://www.ea.com/security/news/anticheat-progress-report) |

### Key Metric: Match Infection Rate (MIR)

EA's primary fairness metric. Measures "how often a regular player would see a cheater in their matches on average." Includes confirmed cheaters (all banned) and suspected cheaters based on detection signals.

MIR is calculated retrospectively — initial readings mature as more data is gathered. For example, December 31 MIR was initially reported as 3.09% but matured to 2.28% after additional analysis.

Source: [EA BF6 January Metrics](https://www.ea.com/games/battlefield/battlefield-6/news/battlefield-6-anticheat-metrics-january)

### Notable Detection Milestones
- "Significant increase" in detecting **stealth cheats** — cheats that deliberately operate at low impact to avoid behavioral detection
- "New ban acceleration method" tested Jan 18, deployed Jan 26 — reduced time-to-ban for detected cheaters

Source: [EA BF6 January Metrics](https://www.ea.com/games/battlefield/battlefield-6/news/battlefield-6-anticheat-metrics-january)

## ARM64 Expansion

EA is actively developing native ARM64 support for Javelin. The March 2026 job listing for "Senior Anti-Cheat Engineer, ARM64" specifies:

**Requirements**:
- Develop a **native ARM64 kernel driver** (not a user-mode shim or x86 translation layer)
- Domain expertise in Windows internals, low-level programming, drivers, compiler toolchains, and CPU intrinsics
- Set up automated build and validation pipelines on ARM hardware

**Technical Challenges Identified**:
- **Memory model differences**: ARM's weakly-ordered memory model vs x86's strong ordering — requires explicit memory barriers and careful atomic operation handling
- **Interrupt architecture**: ARM GIC (Generic Interrupt Controller) vs x86 APIC — ISR handling must be rearchitected
- **Floating-point handling**: different FPU register architecture and calling conventions
- **CPU intrinsics**: x86-specific intrinsics (CPUID, RDTSC, etc.) need ARM64 equivalents (system registers, CNTVCT_EL0, etc.)

**Strategic context**: aligns with NVIDIA's rumored N1/N1X ARM-based PC processors and the broader shift toward Windows on ARM. The listing also mentions charting a path for Linux/Proton support.

Sources: [Tom's Hardware](https://www.tomshardware.com/video-games/pc-gaming/eas-javelin-anti-cheat-is-coming-to-arm-based-systems-soon-new-job-listing-for-windows-on-arm-driver-anticipates-nvidia-n1-n1x-debut-and-pivotal-shift-in-pc-gaming), [VideoCardz](https://videocardz.com/newz/ea-job-listing-points-to-arm64-windows-driver-for-ea-javelin-anticheat), [GamingOnLinux](https://www.gamingonlinux.com/2026/03/ea-javelin-anticheat-job-listing-mentions-future-support-for-linux-and-proton/)

## Javelin vs Other Kernel Anti-Cheats — Comparison

| Aspect | Javelin | Vanguard | EAC | BattlEye |
|--------|---------|----------|-----|----------|
| Developer | EA (in-house) | Riot (in-house) | Epic (acquired) | BattlEye GmbH |
| Ring level | Ring 0 | Ring 0 | Ring 0 | Ring 0 |
| Loads at boot | Yes | Yes | No (game launch) | No (game launch) |
| Secure Boot required | Yes (hard req) | No (recommended) | No | No |
| TPM 2.0 required | Yes | No | No | No |
| HVCI/VBS required | Capable (enforced) | Recommended | No | No |
| Driver blocklist | Yes (active) | Yes (active) | Limited | Limited |
| VM detection | Yes | Yes | Yes | Yes |
| Uninstalls with game | Yes (auto) | Manual uninstall | Yes | Yes |
| ARM64 support | In development | No | No (Proton only) | No |
| Linux/Proton support | Planned | No | Yes (some titles) | No |
| Self-reported accuracy | >99% | Not published | Not published | Not published |

## What's Not Publicly Known

EA deliberately withholds implementation specifics. Key unknowns:
- Exact kernel callbacks registered (likely ObRegisterCallbacks, PsSetCreateProcessNotifyRoutineEx, PsSetLoadImageNotifyRoutine, but unconfirmed)
- Whether Javelin uses ETW providers (likely TI provider given PPL hints)
- Internal driver name and module structure
- Specific signature database format and update mechanism
- Detailed ML model architecture for behavioral detection
- Exact data retention policies and GDPR compliance mechanisms
- Whether Javelin interacts with TPM beyond boot attestation
- Kernel memory scanning implementation details

This opacity is intentional — revealing detection internals would give cheat developers a roadmap for evasion. But it creates legitimate privacy and trust concerns that EA has only partially addressed through third-party audits.

## Relevance to Our Prototype

Javelin validates several design decisions for Owlbear:
1. **Boot-time loading** provides a meaningful trust advantage over game-time loading
2. **Secure Boot enforcement** creates a verified chain that makes BYOVD significantly harder
3. **Driver blocklisting** is a practical necessity, not just theory
4. **Layered detection** (kernel + client + server) outperforms any single layer alone
5. **Per-title customization** — one AC engine, tuned per game — is the production model
6. **ARM64 is the next frontier** — EA hiring specifically for this confirms market direction
7. **MIR as a metric** — measuring match-level impact, not just raw detection count, is more meaningful for player experience
