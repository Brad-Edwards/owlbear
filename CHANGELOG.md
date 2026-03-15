# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-03-15

### Added
- **WP1b: TracerPid polling for debugger detection** (`daemon/debugger_detect.c`): polls `/proc/<pid>/status` for non-zero `TracerPid` every 5s in the watchdog loop. Detects debuggers that attached before daemon start or via methods eBPF hooks don't cover. Emits `OWL_EVENT_PTRACE_ATTEMPT` with `source=OWL_SRC_DAEMON` on 0-to-nonzero state transition. 6 unit tests (TDD).

### Changed
- `scripts/verify.sh`: version bumped to v1.2.0
- `README.md`: updated status (101 tests, 11 suites), added TracerPid mention, removed stale "no anti-debug" limitation

## [1.1.0] - 2026-03-15

### Added
- **WP1a: In-process mprotect injection cheat** (`cheats/mprotect_inject_via_ptrace.c`): realistic code injection attack chain — PTRACE_ATTACH to game, inject mmap+mprotect syscalls into game's execution context via register manipulation and single-stepping. The mprotect(RW->RX) call originates from the game's PID, correctly firing the eBPF LSM `file_mprotect` hook. Supports ARM64 (SVC #0) and x86_64 (syscall). Replaces the skipped E2E assertion with 2 real detection checks.

### Changed
- `scripts/verify.sh`: added `mprotect_inject_via_ptrace` to baseline (assert injection succeeds) and protected (assert PTRACE_ATTEMPT or MPROTECT_EXEC detection) phases. Replaced `assert_skip` for mprotect detection with real assertions. Version bumped to v1.1.0.
- `cheats/Makefile`: builds `mprotect_inject_via_ptrace.bin`

## [1.0.0] - 2026-03-14

### Added
- **eBPF Loading and Enforcement (WP1):**
  - `daemon/bpf_loader.c`: loads/attaches all three BPF skeletons (LSM, tracepoint, kprobe), populates `protected_pids`/`allowed_pids` maps, polls ring buffer via `ring_buffer__poll()`
  - `daemon/bpf_event_convert.c`: pure BPF event → owlbear_event conversion (testable without libbpf)
  - `ebpf/owlbear_lsm.bpf.c`: new `SEC("lsm/file_mprotect")` hook detects RW→RX transitions in protected process
  - `OWL_EVENT_MPROTECT_EXEC` (0x0105) added to events header and BPF common header
  - Graceful degradation: if any BPF program fails, others still operate; kmod-only fallback
- **Event Pipeline (WP2):**
  - `daemon/event_pipeline.c`: unified event processing — policy evaluation → enforcement action → logging. `[ENFORCE] [BLOCK]` log entries when `--enforce` is passed. SIGKILL on `OWL_ACT_KILL`. Periodic signature scan on game `.text` via `/proc/<pid>/maps` + `/proc/<pid>/mem`
  - `daemon/sig_loader.c`: parses `signatures/default.sigs` line format (`NAME:PATTERN`), handles comments and malformed lines
  - Default policy rules: BLOCK on ptrace/proc_mem/vm_readv/vm_writev in enforce mode; LOG on signature matches and module events
- **New Cheat Vectors (WP3):**
  - `cheats/ptrace_writer.c`: PTRACE_ATTACH + PTRACE_POKEDATA to write `health=9999`
  - `cheats/vm_writer.c`: `process_vm_writev()` to write `health=9999`
  - `cheats/mprotect_injector.c`: `mmap(RW)` → write ARM64/x86 shellcode → `mprotect(RX)` → execute
- **Code Integrity (WP4):**
  - `daemon/integrity.c`: CRC32 hash of game `.text` segment at baseline, periodic re-verification. Parses `/proc/<pid>/maps` for `r-xp` segments, emits `OWL_EVENT_CODE_INTEGRITY_FAIL` on mismatch
- **Self-Protection (WP5):**
  - `daemon/self_protect.c`: `prctl(PR_SET_DUMPABLE, 0)` blocks ptrace on daemon. Watchdog checks `/sys/module/owlbear/` existence, ioctl responsiveness, BPF ring buffer fd liveness every 5s
  - `kernel/owlbear_integrity.c`: kprobe on `delete_module` emits `OWL_EVENT_MODULE_UNKNOWN` on any module unload
- **Daemon epoll multiplexer:** replaced blocking `read()` loop with `epoll` on both `/dev/owlbear` fd and BPF ring buffer fd, periodic timer for integrity check (30s) and self-protection watchdog (5s)
- **New tests:** 5 suites (test_bpf_loader, test_sig_loader, test_event_pipeline, test_integrity, test_self_protect) adding 38 tests. Total: 95 C tests across 10 suites
- **verify.sh v2:** three phases (baseline, protected, self-protection), tests all 8 cheats, checks EPERM enforcement from eBPF LSM, integrity baseline capture, module unload detection, daemon survival

### Changed
- `daemon/main.c`: full rewrite — integrates BPF loader, event pipeline, integrity, self-protection, epoll event loop. Adds `--sigs` CLI flag
- `daemon/Makefile`: builds all new source files, links `-lbpf -lelf -lz`, adds `-I../ebpf` for skeleton headers
- `cheats/Makefile`: builds 3 new cheat binaries (ptrace_writer, vm_writer, mprotect_injector)
- `tests/Makefile`: builds 5 new test suites with daemon object dependencies
- `.github/workflows/verify.yml`: E2E verification on Graviton3 via SSM — finds instance by tag, starts if stopped, syncs code, builds eBPF+kernel+userspace, runs unit tests + `verify.sh --upload`
- `deploy/terraform/bootstrap/main.tf`: added `ssm:SendCommand`, `ssm:GetCommandInvocation`, `ssm:DescribeInstanceInformation`, `ec2:StartInstances` permissions for GitHub Actions role
- `deploy/terraform/modules/graviton-dev/userdata.sh`: added `make -C ebpf` to instance bootstrap (generates skeleton headers needed by daemon)

## [0.9.0] - 2026-03-14

### Added
- E2E verification script (`scripts/verify.sh`): adversarial evidence package builder
  - Two-phase design: baseline (no module, cheats succeed) vs protected (module loaded, detection fires)
  - Per-cheat artifact capture: strace log, stdout/stderr, exit code, dmesg diff
  - Assertions on exact `pr_warn` strings from kprobe handlers with correct PIDs
  - PAC false positive regression check across full check interval
  - kprobes list snapshot at module load
  - SHA-256 manifest of all artifacts for tamper detection
  - Self-contained timestamped output directory (`/tmp/owlbear-verify-YYYYMMDD-HHMMSS/`)
  - Machine-generated `summary.txt` with PASS/FAIL/SKIP per assertion — no LLM in the loop
  - `--upload` flag: syncs evidence package to S3 (`owlbear-verification-artifacts` bucket)
  - `--bucket` / `--region` overrides; auto-detects region via IMDSv2
  - EC2 instance identity document captured for provenance (instance ID, account ID)
  - `latest.txt` pointer in S3 for easy retrieval of most recent run
- S3 verification artifacts bucket (`owlbear-verification-artifacts`) in graviton-dev Terraform module
  - Versioning enabled, AES-256 SSE, all public access blocked
  - 90-day lifecycle expiration, 30-day noncurrent version cleanup
  - IAM policy on Graviton instance profile: PutObject, GetObject, ListBucket

## [0.8.0] - 2026-03-14

### Fixed
- ARM64 `extract_vm_rw_target` double-dereference: kernel 6.1+ passes user pt_regs directly, `regs->regs[0]` IS the first syscall arg. Removed invalid pointer cast that caused EFAULT/EIO in cheats
- PAC key false positive: workqueue reads kworker's per-process PAC keys, not the game's. Removed key value comparison, kept only `SCTLR_EL1.EnIA` global enable check
- Demo script address parsing: replaced fragile stderr+sed with info file read
- `strtoull` base 16 hardcoded in cheats: changed to base 0 (auto-detect `0x` prefix)

### Added
- Game info file (`/tmp/owlbear-game.info`): game writes `PID 0xADDR`, unlinks on exit. Shared `GAME_INFO_FILE` constant in `game_state.h`
- Info file fallback in `mem_reader`, `proc_mem_reader`, `ptrace_injector`: run with no args to auto-discover game PID and address
- `ptrace_injector`: real implementation using PTRACE_ATTACH + PTRACE_PEEKDATA word-by-word read, prints stolen state, detaches
- `-no-pie` in game CFLAGS/LDFLAGS for stable addresses across runs
- `test_info_parse` (8 tests): valid format, missing prefix, large address, trailing whitespace, garbage, negative PID, empty file, missing file
- Total test count: 65 (57 C across 5 suites + 11 Python, up from 60)

### Changed
- Demo script uses info file for PID/address discovery with log-parsing fallback
- Demo script runs `ptrace_injector` as cheat #3

## [0.7.0] - 2026-03-13

### Added
- End-to-end demo script (`scripts/demo.sh`): builds, loads module, starts game + daemon, runs each test cheat, shows detection events, cleans up on exit. Handles ARM64 and x86 gracefully.
- GitHub Pages site (`docs/`): Jekyll with minima theme
  - Architecture overview: data flow diagram, why-hybrid rationale, event pipeline, communication table
  - Process monitoring: tracepoint implementation, ptrace kprobe + BPF LSM, defense-in-depth
  - Memory protection: attack vectors, kprobe targets, BPF LSM file_open dentry walk, non-fatal registration
  - ARM64 hardware checks: system register monitoring, debug register scanning, PAC key verification, periodic workqueue trade-offs
  - PAC/MTE/BTI explainer: what each does, anti-cheat applications, hardware availability, x86 comparison
  - ARM64 vs x86: privilege model, memory architecture, I/D cache coherency implications, debug capabilities, kernel patch protection
- GitHub Pages deployment workflow (`.github/workflows/pages.yml`)
- Total test count unchanged: 60 (49 C + 11 Python)

## [0.6.0] - 2026-03-13

### Added
- Terraform bootstrap: S3 state bucket, DynamoDB lock table, GitHub Actions OIDC provider + IAM role with scoped permissions for catalyst-dev (516608939870)
- Graviton dev module: c7g.large (Graviton3, PAC-capable), Amazon Linux 2023 ARM64, SSM Session Manager access, auto-shutdown via EventBridge, userdata installs build deps and clones repo
- Telemetry platform module: API Gateway HTTP API, Lambda (Python 3.12, arm64), DynamoDB tables (events + heartbeats) with TTL, SSM-stored API key, CloudWatch log group
- Environment composition (dev): wires graviton-dev + telemetry-api modules with S3 backend
- CI/CD deploy workflow: OIDC auth to catalyst-dev, terraform plan on PR, apply on merge to main, platform tests as parallel job
- Provisioning scripts: `provision-graviton.sh` (plan/apply/destroy/output), `connect-graviton.sh` (SSM session wrapper)

## [0.5.0] - 2026-03-13

### Added
- Signature scanner (`daemon/scanner.c`): hex byte-pattern matching with `??` wildcards, compiled pattern database, linear scan
- Signature scanner tests (17 tests, TDD): pattern parsing, matching, database operations
- Heartbeat tracker (`daemon/heartbeat.c`): frame count anomaly detection (freeze/rewind), timeout with configurable threshold
- Heartbeat tracker tests (10 tests, TDD): registration, processing, anomalies, timeouts
- Lambda telemetry receiver (`platform/api/handler.py`): POST /events (batched), POST /heartbeat (returns action), GET /events (dashboard query), GET /health
- Lambda handler tests (11 tests): routing, auth (Bearer token), input validation, DynamoDB mocking
- Signature database (`signatures/default.sigs`): 5 rules targeting test cheat string signatures
- Total test count: 60 (49 C across 4 suites + 11 Python)

## [0.4.0] - 2026-03-13

### Added
- eBPF LSM programs: `ptrace_access_check` (deny + log), `file_open` (/proc/pid/mem deny + log), `mmap_file` (PROT_EXEC monitor)
- eBPF tracepoint programs: `sched_process_exec`, `sys_enter_process_vm_readv`, `sys_enter_process_vm_writev`
- eBPF kprobe: `do_init_module` for kernel module load detection
- BPF maps: `protected_pids` (hash), `allowed_pids` (hash), `events` (1MB ringbuf), `event_count` (percpu)
- Shared BPF header (`owlbear_common.bpf.h`): maps, helpers, event struct for ring buffer
- Policy engine (`daemon/policy.c`): rule-based event-type + severity -> action mapping, first-match-wins, wildcard event type support
- Policy engine tests (9 tests, TDD): init defaults, exact match, severity threshold, wildcard, first-match, capacity, action strings, custom default
- Test cheat: `ld_preload_hook` launcher + `preload_hook.so` (replaces damage function for god mode)

## [0.3.0] - 2026-03-13

### Added
- ARM64 system register monitoring: SCTLR_EL1, TCR_EL1, MAIR_EL1, MDSCR_EL1, VBAR_EL1 baseline snapshot at init, periodic re-verification via delayed workqueue (5s interval)
- WXN disable detection: reports if Write-implies-eXecute-Never is cleared (enables W+X pages)
- VBAR_EL1 redirect detection: reports if exception vector table base changes
- MDSCR_EL1 KDE detection: reports if kernel debug is enabled post-init
- Hardware debug register scanning: reads DBGBCR/DBGBVR 0-5 and DBGWCR/DBGWVR 0-3, reports any active breakpoints/watchpoints
- PAC key integrity: captures APIAKeyHi/Lo_EL1 at init, detects substitution (conditional on CONFIG_ARM64_PTR_AUTH + hardware support)
- PAC SCTLR_EL1.EnIA monitoring: detects if pointer authentication is disabled
- Kernel module enumeration: walks loaded module list, reports modules loaded after owlbear
- Non-ARM64 stub: module loads on x86 with ARM64 checks disabled (cross-compile testing)
- Test cheat: `debug_reg_setter` — ptrace attach + PTRACE_SETREGSET NT_ARM_HW_BREAK on ARM64
- Register ID enum and ARM64 bit definitions in `owlbear_arm64.h`

## [0.2.0] - 2026-03-13

### Added
- SPSC lock-free ring buffer with `smp_wmb`/`smp_rmb` barriers for kernel-to-userspace event delivery
- `/dev/owlbear` chardev: blocking read, poll/epoll, ioctl (SET_TARGET, CLEAR_TARGET, GET_STATUS, SET_MODE)
- Process monitoring via `sched_process_fork/exec/exit` tracepoints and `__ptrace_may_access` kprobe
- Memory protection kprobes: `mem_open`, `__arm64_sys_process_vm_readv/writev`, `vm_mmap_pgoff` (PROT_EXEC), `do_init_module`
- Userspace daemon with blocking event loop, structured logging, CLI target/enforce/log configuration
- ncurses test game: mutable game state with health/armor/position/aim, function pointer hook targets
- Test cheats: `mem_reader` (process_vm_readv), `proc_mem_reader` (/proc/pid/mem)
- 13 unit tests: struct sizes, alignment, field offsets, event type ranges, ioctl uniqueness

## [0.1.0] - 2026-03-13

### Added
- Repository structure, Makefiles, Kbuild, cross-compilation support
- Shared event header (`include/owlbear_events.h`): 128-byte event struct, typed payloads, ioctl definitions, heartbeat protocol
- GitHub Actions CI for ARM64 cross-compilation and header validation
- `scripts/setup-dev.sh` for build dependency installation
- Terraform layout for catalyst-dev deployment
