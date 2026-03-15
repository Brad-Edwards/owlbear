# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.6.0] - 2026-03-15

### Added
- `daemon/log.h`: header-only logging macro system with 4 levels (ERR/WARN/INFO/DBG), runtime filtering via `g_owl_log_level`, compile-time DBG gate via `OWL_DEBUG`. ERR/WARN route to stderr, INFO/DBG to stdout. Mirrors kernel module `pr_info`/`pr_warn`/`pr_err` pattern.
- `tests/test_log.c`: 7 unit tests — output routing, level filtering, prefix injection, format interpolation, compile-time DBG elimination
- `--verbose`/`-v` and `--quiet`/`-q` CLI flags for daemon log level control

### Changed
- `daemon/main.c`: migrated ~35 printf/fprintf/perror call sites to OWL_ERR/OWL_WARN/OWL_INFO macros, added `g_owl_log_level` global and `--verbose`/`--quiet` flag parsing
- `daemon/bpf_loader.c`: migrated 15 call sites to log macros, enhanced libbpf callback to respect `g_owl_log_level` for LIBBPF_DEBUG
- `daemon/self_protect.c`: migrated 5 call sites to log macros
- `daemon/integrity.c`: migrated 1 call site to OWL_INFO
- `daemon/vdso_integrity.c`: migrated 1 call site to OWL_INFO
- `tests/Makefile`: added `test_log` to TEST_BINS (18 suites total)

### Fixed
- `daemon/self_protect.c`: dual-logging bug — `owl_selfprotect_watchdog()` wrote "[ALERT] kernel module unloaded!" to both stderr and stdout with explicit flushes. Now single OWL_WARN call to stderr only.
- Alert messages (`[ALERT] ...`) that were incorrectly routed to stdout now go to stderr via OWL_WARN

## [2.5.0] - 2026-03-15

### Added
- WP4: Speed hack detection via multi-clock drift and vDSO integrity
- `daemon/clock_validator.{h,c}`: CLOCK_MONOTONIC vs CLOCK_MONOTONIC_RAW drift detection with 50ms threshold; ARM64 CNTVCT_EL0 cross-check via inline `mrs` instructions
- `daemon/vdso_integrity.{h,c}`: HMAC-SHA256 baseline/check of [vdso] mapping pages; detects runtime vDSO patching (speed hacks bypassing LD_PRELOAD)
- `OWL_EVENT_CLOCK_DRIFT` (0x0700), `OWL_EVENT_VDSO_TAMPER` (0x0701) event types
- `cheats/speed_hook_so.c`: LD_PRELOAD .so that intercepts `clock_gettime(CLOCK_MONOTONIC)` and returns 2x elapsed time
- `cheats/speed_hack.c`: launcher that sets `LD_PRELOAD=speed_hook.so` and execs game
- `tests/test_clock_validator.c`: 7 unit tests (TDD) — drift computation, init, null handling
- `tests/test_vdso_integrity.c`: 5 unit tests (TDD) — maps parsing, init, buffer tamper detection
- 2 E2E assertions in `scripts/verify.sh` for speed_hack baseline + protected phases

### Changed
- `include/owlbear_events.h`: added 0x0700 range comment, CLOCK_DRIFT and VDSO_TAMPER event types
- `daemon/main.c`: clock_validator and vdso_integrity includes, init, event_loop integration (clock check 5s watchdog, vDSO check 30s periodic), event_type_str/print_event cases, policy rules
- `daemon/Makefile`: added `clock_validator.c`, `vdso_integrity.c` to SRCS
- `tests/Makefile`: added `test_clock_validator`, `test_vdso_integrity` test suites
- `cheats/Makefile`: added `speed_hack.c` to CHEAT_SRCS, `speed_hook.so` build rule with `-ldl`
- `scripts/verify.sh`: version bumped to v2.5.0, added speed_hack to preflight + E2E phases

## [2.4.0] - 2026-03-15

### Added
- WP3: Network monitoring via eBPF kprobes (`ebpf/owlbear_net.bpf.c`)
- kprobes on `tcp_v4_connect`, `udp_sendmsg`; filter by protected PID; observe-only
- `OWL_EVENT_NET_CONNECT` (0x0600), `OWL_EVENT_NET_SEND` (0x0601) event types
- `struct owl_payload_network`: dst_addr, dst_port, protocol, bytes, comm
- `daemon/net_allowlist.{h,c}`: static IP allowlist, logs if destination not in list
- `cheats/net_exfil.c`: UDP game state exfiltration cheat
- `tests/test_net_allowlist.c`: 8 unit tests
- 2 BPF conversion tests for network events in `test_bpf_loader.c`

### Changed
- `include/owlbear_events.h`: network event types + payload + union member
- `daemon/bpf_loader.c`: loads owlbear_net skeleton
- `daemon/bpf_event_convert.c`: NET_CONNECT/NET_SEND conversion
- `daemon/event_pipeline.{h,c}`: allowlist integration, updated init signature
- `daemon/main.c`: network event formatting, policy rules, allowlist init

## [2.3.1] - 2026-03-15

### Fixed
- ARM64 ptrace syscall injection: replaced `PTRACE_SINGLESTEP` with `PTRACE_SYSCALL` enter/exit pair for executing injected SVC instructions. `PTRACE_SINGLESTEP` over `SVC #0` on kernel 6.17 ARM64 does not execute the syscall — registers are unchanged after the step. x86_64 path unchanged.
- `read_result()` in `mprotect_inject_via_ptrace.c`: added error check on `PTRACE_GETREGSET` return (previously returned uninitialized stack data on failure)
- mmap return value check: reject 0 as failure (`<= 0` instead of `< 0`), since 0 means the syscall never ran
- LD_PRELOAD detection race condition: `owl_check_preload_env()` now retries up to 3 times with 50ms backoff when `/proc/<pid>/environ` is unreadable. The exec tracepoint fires during `execve()` processing before the new process image is fully set up.

## [2.3.0] - 2026-03-15

### Added
- **WP2: HMAC-SHA256 code integrity** (`daemon/hmac_sha256.c`): replaces CRC32 with HMAC-SHA256 using per-session 256-bit random key from `/dev/urandom`. Uses OpenSSL one-shot `HMAC()` (not deprecated `HMAC_CTX_*`). Graviton3 ARMv8.4 SHA extensions accelerate computation.
- `daemon/hmac_sha256.h`: public API (`owl_hmac_sha256`, `owl_hmac_generate_key`)
- `tests/test_hmac_sha256.c`: 10 unit tests (TDD) — RFC 4231 known-answer vectors, empty/large input, key change, null inputs, key generation, integrity baseline+check, violation detection
- Buffer-based integrity functions (`owl_integrity_baseline_buffer`, `owl_integrity_check_buffer`) for testable verification without /proc I/O
- `scripts/verify.sh`: HMAC-SHA256 baseline assertion in protected phase, ld_preload_hook baseline assertion

### Changed
- `daemon/integrity.h`: `baseline_crc` replaced with `baseline_hmac[32]` + `hmac_key[32]` in `struct owl_integrity`
- `daemon/integrity.c`: baseline and check functions use HMAC-SHA256 via buffer variants; CRC32 retained for heartbeat `state_hash`
- `daemon/Makefile`: added `hmac_sha256.c`, linked `-lssl -lcrypto`
- `tests/Makefile`: added `test_hmac_sha256` suite, updated `test_integrity` linking with OpenSSL
- `tests/test_integrity.c`: init test checks HMAC fields instead of CRC32
- `scripts/verify.sh`: version bumped to v2.3.0
- `README.md`: updated status (v2.3.0, 125 tests, 14 suites), HMAC-SHA256 in daemon description, removed CRC32 limitation
- `deploy/terraform/modules/graviton-dev/userdata.sh`: added `libssl-dev` to build dependencies
- `.github/workflows/ci.yml`: install `libssl-dev` on Graviton before build (OpenSSL headers required for HMAC-SHA256)

## [2.2.0] - 2026-03-15

### Added
- **WP1e: Process tree construction from tracepoint events** (`daemon/process_tree.c`): open-addressing hash map (linear probing, 1024 slots) storing PID -> {parent_pid, comm, birth_time}. Fed by fork/exec/exit events via `owl_ptree_on_event()` in the pipeline. Provides `owl_ptree_is_descendant()` and `owl_ptree_get_chain()` for correlation engine ancestry queries.
- `daemon/process_tree.h`: public API (init, destroy, insert, remove, lookup, is_descendant, get_chain, on_event)
- `tests/test_process_tree.c`: 8 unit tests (TDD) — insert/lookup, parent chain, ancestry chain, descendant check, remove, capacity, null inputs, reinsert after exit

### Changed
- `daemon/event_pipeline.h`: added `struct owl_ptree *ptree` field to pipeline context, added ptree parameter to `owl_pipeline_init()`
- `daemon/event_pipeline.c`: calls `owl_ptree_on_event()` after LD_PRELOAD check for process lifecycle events
- `daemon/main.c`: instantiates `struct owl_ptree`, passes to pipeline init, destroys on cleanup
- `daemon/Makefile`: added `process_tree.c` to SRCS
- `tests/Makefile`: added `test_process_tree` suite, linked `process_tree.o` into `test_event_pipeline`
- `tests/test_event_pipeline.c`: updated `owl_pipeline_init()` calls with NULL ptree parameter

## [2.1.0] - 2026-03-15

### Added
- **WP1d: LD_PRELOAD detection on process exec** (`daemon/preload_detect.c`): scans `/proc/<pid>/environ` for `LD_PRELOAD` on every `PROCESS_EXEC` event. Emits `OWL_EVENT_LIB_UNEXPECTED` (0x0203, severity CRITICAL) with the preload path in the module payload. Pure scanner function + I/O wrapper, stateless one-shot per exec.
- `daemon/preload_detect.h`: public API (`owl_scan_environ_for_preload`, `owl_check_preload_env`)
- `tests/test_preload_detect.c`: 5 unit tests (TDD) — synthetic buffer scan, not-found, null buffer, null output, self-check via /proc
- `scripts/verify.sh`: E2E assertion for `ld_preload_hook` triggering `LIB_UNEXPECTED` in daemon log

### Changed
- `daemon/event_pipeline.c`: calls `pipeline_check_preload()` on `OWL_EVENT_PROCESS_EXEC` events, emits `LIB_UNEXPECTED` if `LD_PRELOAD` found
- `daemon/Makefile`: added `preload_detect.c` to SRCS
- `tests/Makefile`: added `test_preload_detect` suite, linked `preload_detect.o` into `test_event_pipeline`
- `scripts/verify.sh`: version bumped to v2.1.0, added `ld_preload_hook.bin` to preflight checks
- `README.md`: updated status (v2.1.0, 107 tests, 12 suites), added LD_PRELOAD detection

## [2.0.0] - 2026-03-15

### Added
- **WP1c: Block /dev/mem and /dev/kmem via eBPF LSM** (`ebpf/owlbear_lsm.bpf.c`): extends `file_open` hook to unconditionally block `/dev/mem` and `/dev/kmem` opens with -EPERM. Physical memory access bypasses all process-level protections, so no PID allowlist check is performed. Emits `OWL_EVENT_DEV_MEM_ACCESS` (severity CRITICAL, target_pid=0). Detail string distinguishes `/dev/mem` vs `/dev/kmem`.
- `OWL_EVENT_DEV_MEM_ACCESS` (0x0106) in shared event header and BPF common header (breaking: new event type)
- `cheats/dev_mem_reader.c`: attack program that attempts to open `/dev/mem` and `/dev/kmem` and read 256 bytes of raw physical memory
- `tests/test_bpf_loader.c`: conversion test for `OWL_EVENT_DEV_MEM_ACCESS` (102 total tests)
- `scripts/verify.sh`: baseline and protected phase assertions for dev_mem_reader, handles CONFIG_STRICT_DEVMEM (EACCES) gracefully

### Changed
- `daemon/bpf_event_convert.c`: `OWL_EVENT_DEV_MEM_ACCESS` falls through to memory payload conversion
- `daemon/main.c`: `event_type_str()` and `print_event()` handle `DEV_MEM_ACCESS`
- `cheats/Makefile`: builds `dev_mem_reader.bin`
- `scripts/verify.sh`: version bumped to v2.0.0
- `README.md`: updated status (v2.0.0, 102 tests, 9 attack programs), added /dev/mem blocking

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
