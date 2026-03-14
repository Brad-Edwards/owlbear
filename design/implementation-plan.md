# Owlbear Implementation Plan: ARM64 Kernel-Mode Anti-Cheat Prototype

## Project Purpose

A functional ARM64 kernel-mode anti-cheat prototype that:
1. Covers all major anti-cheat subsystems (process monitoring, memory protection, integrity verification, hardware checks, signature scanning, behavioral analysis)
2. Serves as a personal learning tool for kernel security and anti-cheat internals
3. Produces GitHub Pages educational content for others to learn about anti-cheat
4. Demonstrates the skills needed for a senior security PM (anti-cheat) role

## Repository Structure

```
owlbear/
├── CHANGELOG.md
├── README.md
├── LICENSE
├── Makefile                          # Top-level orchestrator
│
├── docs/                             # GitHub Pages source (Jekyll)
│   ├── _config.yml
│   ├── index.md
│   ├── architecture/
│   │   ├── overview.md               # Hybrid architecture explained
│   │   ├── kernel-module.md
│   │   ├── ebpf-programs.md
│   │   ├── userspace-daemon.md
│   │   └── communication.md          # IPC: chardev + ringbuf
│   ├── subsystems/
│   │   ├── process-monitoring.md
│   │   ├── memory-protection.md
│   │   ├── integrity-verification.md
│   │   ├── hardware-checks.md        # ARM64 system regs, debug regs, PAC
│   │   ├── signature-scanning.md
│   │   └── behavioral-detection.md
│   ├── arm64/
│   │   ├── pac-mte-bti.md
│   │   ├── exception-levels.md
│   │   └── vs-x86.md
│   ├── tutorials/
│   │   ├── building.md
│   │   ├── testing.md
│   │   └── running-on-graviton.md
│   └── assets/
│       └── diagrams/
│
├── research/                         # 9 existing research documents
│
├── design/                           # This plan
│   └── implementation-plan.md
│
├── kernel/                           # Kernel module (C, Kbuild)
│   ├── Kbuild
│   ├── Makefile
│   ├── owlbear_main.c               # Module init/exit, chardev registration
│   ├── owlbear_chardev.c            # Character device for ioctl
│   ├── owlbear_chardev.h
│   ├── owlbear_process.c            # Process monitoring (tracepoints)
│   ├── owlbear_process.h
│   ├── owlbear_memory.c             # Memory protection hooks
│   ├── owlbear_memory.h
│   ├── owlbear_integrity.c          # Code section hashing, module enumeration
│   ├── owlbear_integrity.h
│   ├── owlbear_arm64.c              # ARM64 HW checks: sysregs, debug regs, PAC
│   ├── owlbear_arm64.h
│   ├── owlbear_events.h             # Shared event structures (kernel <-> userspace)
│   └── owlbear_common.h
│
├── ebpf/                             # eBPF programs (C + libbpf)
│   ├── Makefile
│   ├── owlbear_lsm.bpf.c           # LSM hooks (ptrace, file_open, mmap)
│   ├── owlbear_trace.bpf.c         # Tracepoints (process lifecycle)
│   ├── owlbear_kprobe.bpf.c        # Kprobes (module load, vm_readv)
│   ├── owlbear_maps.h              # BPF map definitions
│   └── owlbear_events.h            # Event structures (shared with userspace)
│
├── daemon/                           # Userspace daemon (C, libbpf + ioctl)
│   ├── Makefile
│   ├── main.c                       # Entry, signal handling, main loop
│   ├── config.c / config.h          # Configuration loading
│   ├── events.c / events.h          # Event processing pipeline
│   ├── ringbuf.c / ringbuf.h        # BPF ring buffer consumer
│   ├── chardev.c / chardev.h        # Kernel module ioctl interface
│   ├── scanner.c / scanner.h        # Signature scanning engine
│   ├── signatures.c / signatures.h  # Signature database loader
│   ├── policy.c / policy.h          # Policy engine (observe/block/kill)
│   ├── heartbeat.c / heartbeat.h    # Watchdog + heartbeat logic
│   ├── logger.c / logger.h          # Structured logging (JSON)
│   └── bpf_loader.c / bpf_loader.h # eBPF program loading
│
├── game/                             # Test "game" application (C)
│   ├── Makefile
│   ├── main.c                       # Game loop, state management
│   ├── game_state.h                 # Player health, position, aim, function ptrs
│   ├── renderer.c / renderer.h     # Terminal-based rendering (ncurses)
│   ├── input.c / input.h
│   ├── ac_client.c / ac_client.h   # Anti-cheat client integration
│   └── libgame_physics.c           # Shared library (tests library verification)
│
├── cheats/                           # Test cheat programs (C)
│   ├── Makefile
│   ├── README.md                    # Documents each cheat + expected detection
│   ├── mem_reader.c                 # process_vm_readv reader
│   ├── ptrace_injector.c           # ptrace attach + shellcode injection
│   ├── proc_mem_reader.c           # /proc/pid/mem reader
│   ├── ld_preload_hook.c           # LD_PRELOAD launcher
│   ├── preload_hook.so.c           # Hook shared object
│   ├── debug_reg_setter.c          # HW debug register setter
│   └── kernel_reader/              # Kernel module cheat
│       ├── Kbuild
│       ├── Makefile
│       └── cheat_kmod.c
│
├── signatures/                      # Signature database
│   └── default.sigs
│
├── configs/                          # Runtime configuration
│   ├── owlbear.conf
│   └── policy.conf
│
├── platform/                         # Telemetry receiver (Python/Lambda)
│   ├── api/
│   │   ├── handler.py               # Lambda handler: receive events + heartbeats
│   │   ├── requirements.txt
│   │   └── tests/
│   │       └── test_handler.py
│   ├── dashboard/                   # Static dashboard (HTML/JS, served from S3)
│   │   ├── index.html
│   │   ├── events.js                # Fetch + render events from API
│   │   └── style.css
│   └── README.md
│
├── deploy/                           # Infrastructure-as-code (Terraform)
│   └── terraform/
│       ├── bootstrap/               # State backend + OIDC (run once manually)
│       │   ├── main.tf
│       │   ├── variables.tf
│       │   ├── outputs.tf
│       │   └── terraform.tfvars
│       ├── modules/
│       │   ├── graviton-dev/        # ARM64 dev instance (c7g.large, spot)
│       │   │   ├── main.tf
│       │   │   ├── variables.tf
│       │   │   ├── outputs.tf
│       │   │   └── userdata.sh      # Install deps, clone repo, build
│       │   ├── telemetry-api/       # API Gateway + Lambda
│       │   │   ├── main.tf
│       │   │   ├── variables.tf
│       │   │   └── outputs.tf
│       │   └── telemetry-store/     # DynamoDB table for events
│       │       ├── main.tf
│       │       ├── variables.tf
│       │       └── outputs.tf
│       └── environments/
│           └── dev/
│               ├── main.tf
│               ├── variables.tf
│               ├── terraform.tfvars
│               └── backend.tf       # s3://owlbear-terraform-state-catalyst-dev
│
├── scripts/                          # Development utilities
│   ├── setup-dev.sh
│   ├── build-all.sh
│   ├── load-module.sh
│   ├── run-tests.sh
│   ├── demo.sh                      # Full end-to-end demo
│   ├── generate-vmlinux.sh
│   ├── provision-graviton.sh        # Spin up ARM64 dev box via Terraform
│   └── deploy-platform.sh           # Deploy telemetry platform
│
├── tests/
│   ├── Makefile
│   ├── test_harness.c / .h
│   ├── test_events.c
│   ├── test_scanner.c
│   ├── test_policy.c
│   └── integration/
│       ├── test_process_monitor.sh
│       ├── test_memory_protection.sh
│       ├── test_cheat_detection.sh
│       └── test_full_pipeline.sh
│
├── .github/
│   └── workflows/
│       ├── build.yml                # Cross-compile for ARM64
│       ├── test.yml                 # Unit tests
│       └── pages.yml                # Deploy GitHub Pages
│
└── .gitignore
```

## Technology Choices

| Component | Language | Tooling | Rationale |
|-----------|----------|---------|-----------|
| Kernel module | C (C11) | Kbuild, aarch64-linux-gnu-gcc | Required by Linux kernel module framework |
| eBPF programs | C (restricted) | clang/LLVM, libbpf, bpftool | libbpf standard; CO-RE requires clang |
| Userspace daemon | C (C11) | gcc/clang, libbpf | Same language as kernel; natural for systems code |
| Test game | C (C11) | gcc/clang, ncurses | Minimal deps; ncurses ubiquitous |
| Test cheats | C (C11) | gcc/clang | Must call ptrace, process_vm_readv directly |
| Signatures | Custom text format | - | Hex bytes + wildcards |
| Build system | GNU Make | make | Standard for kernel modules |
| Documentation | Markdown + Jekyll | GitHub Pages | Free hosting, Mermaid support |
| CI | GitHub Actions | ubuntu + cross-compile | ARM64 cross-compile on x86 runners |
| Telemetry API | Python 3.12 | Lambda + API Gateway | Fastest path to a working receiver; Lambda is free-tier friendly |
| Telemetry store | - | DynamoDB | Serverless, pay-per-request, zero ops |
| Dashboard | HTML/JS | S3 static site | No framework needed; fetches from API |
| Infrastructure | HCL | Terraform 1.7+ | Matches existing catalyst-dev patterns |
| ARM64 dev box | - | EC2 c7g.large (Graviton3) | Native ARM64 with PAC support, ~$0.0725/hr |

**Why C for the on-box components**: the entire value proposition is demonstrating deep systems knowledge. C shows comfort with the same APIs used by production anti-cheat code. The prototype is small enough that Rust's safety benefits are marginal, while C demonstrates the skill set interviewers for this role expect.

**Why Python for the telemetry platform**: it's a thin receiver, not performance-critical. Python on Lambda is the fastest path to a working backend. The interesting engineering is on-box (kernel/eBPF/daemon), not in the cloud receiver.

## Shared Event Contract

This header is the contract between all three components (kernel module, eBPF, daemon):

```c
enum owlbear_event_type {
    OWL_EVENT_PROCESS_CREATE,
    OWL_EVENT_PROCESS_EXIT,
    OWL_EVENT_PTRACE_ATTEMPT,
    OWL_EVENT_PROC_MEM_ACCESS,
    OWL_EVENT_VM_READV_ATTEMPT,
    OWL_EVENT_EXEC_MMAP,
    OWL_EVENT_MODULE_LOAD,
    OWL_EVENT_DEBUG_REG_ACTIVE,
    OWL_EVENT_SYSREG_TAMPER,
    OWL_EVENT_CODE_INTEGRITY_FAIL,
    OWL_EVENT_SIGNATURE_MATCH,
    OWL_EVENT_PAC_KEY_CHANGED,
};

struct owlbear_event {
    __u64 timestamp_ns;
    __u32 event_type;
    __u32 pid;
    __u32 target_pid;
    __u32 severity;      // 0=info, 1=warn, 2=critical
    char  comm[16];
    union { /* event-type-specific data */ };
};
```

## Phased Implementation

### Phase 0: Project Scaffolding (1-2 days)

**Deliverables:**
- Complete repo structure with all directories and stub Makefiles
- Top-level Makefile with targets: all, kernel, ebpf, daemon, game, cheats, clean
- `scripts/setup-dev.sh` installing all build dependencies
- README.md with architecture diagram (Mermaid), build instructions, project status table
- CHANGELOG.md initialized
- .gitignore extended for kernel build artifacts
- GitHub Actions CI for cross-compilation
- Shared header `owlbear_events.h` defining the event structure

### Phase 1: Kernel Module Foundation (3-4 days)

**Deliverables:**
1. Loadable kernel module with module params (target_pid, enforce mode)
2. `/dev/owlbear` character device with ioctl + blocking read for events
3. Process monitoring via sched_process_fork/exec/exit tracepoints
4. Basic ptrace protection (kprobe on ptrace syscall, block/log for protected PID)
5. Daemon skeleton: opens /dev/owlbear, reads events, pretty-prints to stdout + log

**Tests:**
- Load module, create process, verify event in daemon log
- Attempt strace on protected PID, verify blocked/logged

### Phase 2: Memory Protection + Test Game (4-5 days)

**Deliverables:**
1. Block /proc/pid/mem access to protected PID (kprobe on mem_open)
2. Block process_vm_readv/writev to protected PID (kprobe on process_vm_rw_core)
3. Monitor PROT_EXEC mmap in protected process
4. Kernel module load enumeration and reporting
5. Test game (ncurses): health bar, position, aim angles, function pointers, shared lib
6. Test cheats: mem_reader (process_vm_readv), proc_mem_reader (/proc/pid/mem)

### Phase 3: ARM64 Hardware Checks + Integrity (4-5 days)

**Deliverables:**
1. System register snapshots: SCTLR_EL1, TCR_EL1, MAIR_EL1, MDSCR_EL1, VBAR_EL1
2. Periodic re-verification (workqueue, every 5s), check WXN/MMU/cache bits
3. Debug register monitoring: DBGBCR/DBGBVR 0-15, DBGWCR/DBGWVR 0-15
4. PAC key integrity (APIAKeyHi/Lo_EL1), conditional on hardware support
5. Exception vector table verification (VBAR_EL1 + hash)
6. Code section hashing of game binary .text section
7. Shared library enumeration via /proc/pid/maps
8. Test cheats: debug_reg_setter, ptrace_injector

**This is the phase that makes the project distinctly ARM64.** PAC/debug register/system register checks demonstrate architecture-specific knowledge that maps directly to the EA Javelin ARM64 job listing.

### Phase 4: eBPF Integration (5-6 days)

**Deliverables:**
1. LSM hook programs: ptrace_access_check, file_open, mmap_file
2. Tracepoint programs: sched_process_exec/exit, sys_enter_process_vm_readv/writev
3. Kprobe programs: load_module, __vm_mmap_locked
4. BPF maps: protected_pids (hash), allowed_pids (hash), events (ringbuf), access tracking (percpu_hash)
5. Daemon eBPF integration: libbpf skeleton, map population, ring buffer consumer
6. Unified event stream merging eBPF and kernel module events
7. Policy engine: per-event-type actions (observe/log/block/kill), hot-reload on SIGHUP
8. Test cheat: ld_preload_hook

**Demonstrates the hybrid architecture**: eBPF for broad monitoring, kernel module for hardware checks.

## Detection Matrix

| Cheat Technique | Detection Method | Component | Phase |
|----------------|-----------------|-----------|-------|
| process_vm_readv | Kprobe + LSM hook | Kernel + eBPF | 2, 4 |
| /proc/pid/mem read | Kprobe + LSM file_open | Kernel + eBPF | 2, 4 |
| ptrace attach | Kprobe + LSM ptrace_access_check | Kernel + eBPF | 1, 4 |
| LD_PRELOAD hook | Module enumeration + code integrity | Kernel + Daemon | 3, 4 |
| HW debug registers | ARM64 debug register scan | Kernel | 3 |
| Code modification | .text section hashing | Kernel + Daemon | 3, 5 |
| Kernel module cheat | Module load monitoring | Kernel + eBPF | 2, 4 |
| Cheat binary in memory | Signature scanning | Daemon | 5 |
| Repeated access attempts | Behavioral threshold | Daemon | 5 |
| System register tampering | ARM64 sysreg verification | Kernel | 3 |
| PAC key substitution | PAC key monitoring | Kernel | 3 |
| Vector table redirection | VBAR_EL1 verification | Kernel | 3 |

### Phase 5: Heartbeat + Telemetry Platform (4-5 days)

Upgrades the daemon from local-logging-only to a real client-server architecture.

**Deliverables:**

1. **Bidirectional heartbeat protocol** (`daemon/heartbeat.c`):
   - Game -> Daemon (Unix socket, every 2s): PID, frame count, state hash
   - Daemon -> Platform (HTTPS, every 15s): game PID, event count, severity max, system health (eBPF attached? kmod loaded?)
   - Platform -> Daemon (response): action (continue/increase_monitoring/kill_game), signature DB version

2. **Telemetry client** (`daemon/telemetry.c`):
   - Batch events locally (50 events or 10 seconds, whichever first)
   - Flush to platform API over HTTPS (libcurl)
   - Retry with exponential backoff if platform unreachable
   - Events buffer locally and never drop

3. **Telemetry API** (`platform/api/handler.py`):
   - Lambda function behind API Gateway
   - POST /events: receive batched detection events, write to DynamoDB
   - POST /heartbeat: receive daemon heartbeat, return action + sig version
   - GET /events: query recent events (for dashboard)
   - API key authentication (stored in SSM Parameter Store)

4. **Telemetry store** (DynamoDB):
   - Events table: partition key = game_session_id, sort key = timestamp_ns
   - Heartbeats table: partition key = instance_id, sort key = timestamp
   - TTL: auto-expire events after 7 days (cost control)

5. **Dashboard** (`platform/dashboard/`):
   - Static HTML/JS served from S3
   - Fetches recent events from API, renders detection timeline
   - Shows active sessions with heartbeat status (alive/stale/dead)
   - Color-coded severity (info=grey, warn=yellow, critical=red)
   - Not fancy -- functional. Proves the pipeline works end-to-end.

6. **Signature scanning engine** (`daemon/scanner.c`):
   - Pattern format: hex bytes + wildcards
   - Load patterns from `signatures/default.sigs`
   - Scan game process memory on launch + periodically (30s)
   - Signature definitions for each test cheat binary

7. **Behavioral thresholds** (`daemon/events.c`):
   - Track event frequency per process
   - >5 blocked ptrace attempts in 60s = elevated severity
   - process_vm_readv + PROT_EXEC mmap from same PID = high confidence cheat

8. **Test cheat**: kernel_reader (kernel module cheat)

### Phase 6: AWS Deployment + CI/CD (3-4 days)

**Deliverables:**

1. **Terraform bootstrap** (`deploy/terraform/bootstrap/`):
   - S3 state bucket: `owlbear-terraform-state-catalyst-dev`
   - DynamoDB lock table: `owlbear-terraform-lock`
   - GitHub Actions OIDC provider (reuse existing in catalyst-dev if available)
   - IAM role for GitHub Actions with scoped permissions
   - Follows exact Ground-Control bootstrap pattern

2. **Graviton dev instance module** (`deploy/terraform/modules/graviton-dev/`):
   - c7g.large spot instance (ARM64 Graviton, ~$5/mo as spot)
   - Amazon Linux 2023 ARM64 AMI
   - Userdata script: install gcc, clang, llvm, libbpf-dev, kernel-devel, ncurses-devel
   - SSM Session Manager access (no SSH key management, no public IP needed)
   - Auto-shutdown at 11pm (matches Shifter dev-box pattern)
   - Security group: egress-only (SSM doesn't need inbound)
   - Instance profile with SSM permissions

3. **Telemetry platform module** (`deploy/terraform/modules/telemetry-api/`):
   - API Gateway HTTP API
   - Lambda function (Python 3.12, ARM64 runtime for consistency)
   - DynamoDB tables (events + heartbeats, PAY_PER_REQUEST)
   - SSM parameter for API key
   - S3 bucket for dashboard static site
   - IAM roles with least-privilege

4. **Environment composition** (`deploy/terraform/environments/dev/`):
   - Composes graviton-dev + telemetry-api + telemetry-store modules
   - terraform.tfvars: instance type, auto-shutdown schedule, TTL settings

5. **CI/CD workflows** (`.github/workflows/`):
   - `build.yml`: cross-compile all ARM64 binaries on x86 runner, upload as artifact
   - `test.yml`: unit tests for daemon (scanner, policy, events) + platform (handler)
   - `deploy.yml`: Terraform plan on PR, apply on merge to main (OIDC to catalyst-dev)
   - `pages.yml`: build and deploy Jekyll site to GitHub Pages
   - Path-filter based: kernel/ changes trigger build, deploy/ changes trigger terraform, docs/ changes trigger pages

6. **Provisioning scripts**:
   - `scripts/provision-graviton.sh`: wrapper around `terraform apply` for the dev environment
   - `scripts/deploy-platform.sh`: package Lambda, deploy via Terraform
   - `scripts/connect-graviton.sh`: `aws ssm start-session` wrapper

### Phase 7: Demo + Polish + GitHub Pages (3-4 days)

**Deliverables:**
1. `scripts/demo.sh`: automated build, load, run game, run each cheat, show detections, clean teardown
2. GitHub Pages Jekyll site with architecture diagrams, per-subsystem deep dives, ARM64 explainer, detection matrix, build tutorial
3. README polish: architecture diagram, detection matrix table, status table, links to Pages
4. Dashboard screenshot/recording in docs showing end-to-end detection pipeline

## Full System Architecture

```
                          catalyst-dev (AWS)
                    +--------------------------+
                    |  API Gateway             |
                    |    |                     |
 Graviton VM        |  Lambda (handler.py)     |
+---------------+   |    |                     |
| Game Process  |   |  DynamoDB (events)       |
|   |heartbeat  |   |    |                     |
|   v           |   |  S3 (dashboard)          |
| Daemon -------+-->|    |                     |
|   |    HTTPS  |   |  CloudFront (optional)   |
|   |           |   +--------------------------+
|   +--- /dev/owlbear ---|
|   |                    |
|   +--- BPF ringbuf ----|
|                        |
| Kernel Module    eBPF  |
| (ARM64 HW)    (LSM/TP)|
+---------------+--------+
```

## Heartbeat Protocol

```c
// Game -> Daemon (local Unix socket, every 2 seconds)
struct heartbeat_msg {
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t frame_count;     // Detects freeze/tamper
    uint32_t state_hash;      // Detects memory modification
};

// Daemon -> Platform (HTTPS POST /heartbeat, every 15 seconds)
struct platform_heartbeat {
    uint64_t timestamp_ns;
    uint32_t game_pid;
    uint32_t events_since_last;
    uint32_t severity_max;
    char     hostname[64];
    char     kernel_version[64];
    bool     ebpf_attached;
    bool     kmod_loaded;
};

// Platform -> Daemon (response body)
struct platform_response {
    uint32_t action;          // 0=continue, 1=increase_monitoring, 2=kill_game
    uint32_t sig_version;     // Trigger signature DB update if newer
};
```

The platform response gives server-side kill switch capability -- if server-side analysis flags something the client missed, the platform can instruct the daemon to terminate the game. This is how production ACs work.

## What Stays Documentation-Only

Too complex for prototype, discussed in GitHub Pages:
- TrustZone integration (requires OP-TEE setup)
- MTE-based memory tagging (requires ARMv8.5+ hardware)
- DMA/FPGA detection (requires specialized hardware)
- ML-based behavioral detection (prototype uses simple thresholds)
- Full Aho-Corasick multi-pattern matching (prototype uses linear scan)
- Encrypted IPC between components
- Full anti-tamper beyond self-integrity hashing
- Ban/enforcement infrastructure (prototype logs detections; production would ban)

## What Makes This Impressive

1. **Working kernel code** -- most portfolios are userspace-only
2. **ARM64-specific** -- maps to EA Javelin ARM64 expansion; PAC/debug register checks are rare
3. **Hybrid architecture** -- eBPF + kernel module with clear reasoning for each
4. **End-to-end pipeline** -- game -> kernel + eBPF -> daemon -> platform -> dashboard
5. **Cloud telemetry** -- real client-server architecture, not just local logging
6. **Infrastructure-as-code** -- Terraform to catalyst-dev, GitHub Actions CI/CD, Graviton dev box
7. **Test cheats prove detection works** -- offense + defense shows security depth
8. **Educational content** -- GitHub Pages demonstrates communication skills critical for PM role
9. **Research-backed** -- every decision traces to 9 research documents
10. **Detection matrix** -- the PM artifact that ties it all together

## Timeline

| Phase | Duration | Cumulative |
|-------|----------|------------|
| 0: Scaffolding | 1-2 days | 1-2 days |
| 1: Kernel Module Foundation | 3-4 days | 4-6 days |
| 2: Memory Protection + Game | 4-5 days | 8-11 days |
| 3: ARM64 Hardware Checks | 4-5 days | 12-16 days |
| 4: eBPF Integration | 5-6 days | 17-22 days |
| 5: Heartbeat + Telemetry Platform | 4-5 days | 21-27 days |
| 6: AWS Deployment + CI/CD | 3-4 days | 24-31 days |
| 7: Demo + Polish + Pages | 3-4 days | 27-35 days |

~5-6 weeks of focused work. Each phase is independently demonstrable.

**Minimum viable portfolio (Phases 0-3)**: ~2 weeks. Working ARM64 kernel module with hardware checks.

**Full system (Phases 0-7)**: ~5 weeks. Kernel through cloud with CI/CD and educational content.

**Cost**: Graviton spot instance ~$5/mo + Lambda/DynamoDB/API Gateway within free tier at prototype scale. Total AWS spend: under $10/month.
