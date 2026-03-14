# Owlbear Research

Technical research artifacts for ARM64 kernel-mode anti-cheat prototype design.

## Documents

| File | Topic |
|------|-------|
| `01-anti-cheat-architecture-overview.md` | Layered trust model (corrected Ring -1 vs Ring 0 distinction), commercial system internals (EAC, BattlEye, Vanguard, Javelin), detection taxonomy, kernel callback infrastructure, communication channels |
| `02-kernel-mode-techniques-x86.md` | Windows driver model, PatchGuard, memory scanning, handle interception, HVCI/VBS, ETW, minifilters, debug registers, MSR-based hooks |
| `03-arm64-kernel-anti-cheat.md` | ARM64 exception levels, system registers, PAC/MTE/BTI, Linux kernel module architecture, TrustZone, Stage-2 translation, vector table monitoring, PMU-based detection |
| `04-cheat-techniques-and-bypasses.md` | External memory access methods, code injection, memory manipulation, rendering exploits, kernel-mode cheat architecture, BYOVD, callback removal, anti-analysis |
| `05-ebpf-for-anti-cheat.md` | eBPF program types for AC, LSM hooks, tracepoints, kprobes, BPF maps, CO-RE portability, Tetragon framework, eBPF limitations, hybrid architecture |
| `06-prototype-design-considerations.md` | Platform decisions, phased build plan, test application design, dev environment, design decisions, threat model, interview discussion points |
| `07-javelin-deep-dive.md` | EA Javelin: full history (PunkBuster->FairFight->EAC->Javelin), Ring 0 architecture, Secure Boot/TPM/HVCI enforcement, driver blocklisting, detection layers, LSASS controversy, team structure, BF6 metrics, ARM64 expansion, comparison table vs Vanguard/EAC/BattlEye. All sourced. |
| `08-anti-cheat-vs-edr-comparison.md` | AC vs EDR deep technical comparison: shared kernel callback infrastructure, ETW/PPL gap, ELAM vs boot-start drivers, self-protection (PPL vs roll-your-own), detection philosophy (prevent vs respond), memory scanning approaches, behavioral ML, BYOVD crossover (AC drivers weaponized against EDR), evasion techniques shared by both, CrowdStrike crash lesson, convergence trends. All sourced. |
| `09-anti-cheat-product-metrics.md` | PM metrics deep dive: MIR (EA), Time-to-Action/Detection (Riot), VACNet conviction rate (Valve), ban accuracy, cheat supply disruption, PUBG operational metrics, business impact (retention/revenue surveys), performance overhead, gaps in public data, proposed interview metric framework. All sourced with honest "no data available" callouts. |
