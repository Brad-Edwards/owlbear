# Owlbear

Anti-cheat and EDR prototype. ARM64 Linux, kernel module + eBPF + userspace daemon. Built to learn how kernel-level security monitoring works by building one.

Not production software.

## What's here

Runs on Graviton3 (c7g.large), Ubuntu 24.04, kernel 6.17.

- **kernel/** - loadable module. Kprobes on ptrace, /proc/pid/mem, process_vm_readv/writev, mmap, module load/unload. ARM64 system register monitoring. Chardev for event delivery.
- **ebpf/** - BPF LSM hooks returning -EPERM (ptrace_access_check, file_open for /proc/pid/mem + /dev/mem + /dev/kmem, file_mprotect). Tracepoints. Kprobe on do_init_module. Ring buffer to userspace.
- **daemon/** - epoll on chardev + BPF ring buffer. Policy engine. Signature scanner. HMAC-SHA256 code integrity. Self-protection watchdog. TracerPid debugger detection. LD_PRELOAD environ scanning. Process ancestry tree for correlation.
- **game/** - ncurses test target. Mutable state, function pointers, exported address.
- **cheats/** - 9 attack programs: process_vm_readv, /proc/pid/mem, /dev/mem, ptrace read, ptrace write, process_vm_writev, LD_PRELOAD, mprotect injection, debug registers.
- **platform/** - Lambda + API Gateway + DynamoDB telemetry receiver.
- **scripts/verify.sh** - E2E test. Baseline (cheats succeed) vs protected (cheats blocked). Machine-generated results.

## Status

v2.3.0. 125 unit tests, 14 suites. eBPF LSM returns EPERM on ptrace, /proc/pid/mem, /dev/mem, /dev/kmem, process_vm_writev. Module can't be unloaded while daemon runs. TracerPid polling detects debuggers attached before daemon start. LD_PRELOAD detection on exec. Process tree tracks ancestry for correlation engine.

Prototype limitations: linear signature scan, no fleet management.

## Getting started

### Existing instance

Pre-provisioned Graviton3 in us-east-2 (catalyst-dev). Already built.

```bash
./scripts/connect-graviton.sh       # SSM session

# On the instance:
cd ~/owlbear
sudo scripts/verify.sh              # E2E, ~2 min
```

Interactive:

```bash
# T1: game
./game/owlbear-game

# T2: protection
sudo insmod kernel/owlbear.ko target_pid=$(pidof owlbear-game)
sudo ./daemon/owlbeard --target $(pidof owlbear-game) --enforce

# T3: cheats (get blocked)
./cheats/ptrace_writer.bin           # EPERM
./cheats/proc_mem_reader.bin         # EPERM
./cheats/mem_reader.bin              # detected
```

### New instance

```bash
cd deploy/terraform/environments/dev
terraform init && terraform apply
```

Userdata installs deps, clones, builds. ~5 min.

### Local ARM64

```bash
./scripts/setup-dev.sh
make -C ebpf
make all
make test
sudo scripts/verify.sh
```

## What you can learn

- Kernel kprobes intercepting syscalls and internal functions
- eBPF LSM returning -EPERM from BPF programs
- BPF CO-RE compilation, skeleton loading, attachment
- Chardev + ring buffer + epoll event delivery
- ARM64 system register monitoring (SCTLR_EL1, MDSCR_EL1, VBAR_EL1)
- PAC and debug register scanning on Graviton3
- Why anti-cheat and EDR use the same kernel infrastructure
- Why eBPF LSM is replacing custom kernel drivers

## Anti-cheat vs EDR

Same plumbing. Kprobes + eBPF LSM is how CrowdStrike, SentinelOne, and Cilium Tetragon work. Anti-cheat protects one process from everything else. EDR protects the system from specific threats. This prototype sits in the overlap.

## Docs

[GitHub Pages site](https://brad-edwards.github.io/owlbear/)

## License

[LICENSE](LICENSE)
