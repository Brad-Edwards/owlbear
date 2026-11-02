# Experiment interfaces, version 1

Use the existing foreground CLI and process exit status for lifecycle. No
terminal is required by the daemon. The game retains `--no-curses` and its
interactive ncurses default. Controllers own the processes they start and
must wait for them to exit. Loading/unloading the module remains explicit.
Only one daemon may control a module at a time.

Run this example from a root shell (device and BPF access require privileges):

```sh
run_dir=$(mktemp -d /root/owlbear-run.XXXXXX)
./game/owlbear-game --no-curses > "$run_dir/game.log" 2>&1 &
game_pid=$!
insmod kernel/owlbear.ko target_pid="$game_pid"
./daemon/owlbeard --target "$game_pid" --enforce \
  --sensors lsm,trace,kprobe,net --control "$run_dir/control.sock" \
  --events "$run_dir/events.jsonl" > "$run_dir/daemon.log" 2>&1 &
daemon_pid=$!
```

Socket and evidence paths must be new. Neither existing files nor existing
sockets are replaced.
`--sensors all` is the default; `none` disables all BPF groups. Kernel sensors
and daemon checks remain enabled. This version supports BPF group selection,
not individual hooks. Observe mode (omit `--enforce`) permits the operations
that Owlbear's LSM would otherwise deny; other kernel security policies may
still deny them. Changing modes or groups requires stopping and starting a
new daemon with new artifact paths. This keeps each run's configuration fixed.

```sh
scripts/owlbearctl.py --socket "$run_dir/control.sock" health > manifest.json
scripts/owlbearctl.py --socket "$run_dir/control.sock" reset
scripts/owlbearctl.py --socket "$run_dir/control.sock" flush > flush.json
scripts/owlbearctl.py --socket "$run_dir/control.sock" stop > stopped.json
wait "$daemon_pid"
kill "$game_pid"
wait "$game_pid"
rmmod owlbear
```

Run the client with the same user as the daemon. Commands return one JSON
object and exit 0 only when `ok` is true. Health may succeed with `ready:false`:
that is a valid inspection of an unrealized condition. Controllers must check
readiness before experiments. Save health responses at run boundaries as run
manifests; save the configuration CLI and game PID alongside them. A stop
reply acknowledges final draining and durable local event output, then the
daemon exits, detaches BPF and clears the kernel target and enforcement.
SIGTERM/SIGINT also clean up; use `flush` first if durable acknowledgement is
required. Fatal startup errors return nonzero and remove the socket.

Reset starts a new evidence epoch, clears pipeline action/event/signature
counters and process ancestry. It does not restart the game, reset kernel
loss counters, discard queued events, or rebaseline integrity checks. For an
independent trial restart the game, daemon and module. Flush drains up to
4096 queued kernel records plus currently available BPF records, calls
`fflush` and `fsync` on the JSONL stream and reports errors. It is a bounded
snapshot while producers continue, not a producer barrier. Save its reply.

## Wire and manifest schema: `owlbear.control.v1`

AF_UNIX SOCK_SEQPACKET, one ASCII packet `owlbear.control.v1 COMMAND` per
connection, maximum 63 bytes, no newline. Reply: one JSON packet. Unknown
commands/versions return `ok:false`. Clients must allow additional JSON keys;
incompatible changes require a new schema identifier.

| Field | Type and meaning |
| --- | --- |
| schema | constant `owlbear.control.v1` |
| ok | boolean, command completed |
| ready | boolean, loop ready, target alive, kernel readback matches, all requested BPF groups attached/configured, evidence stream healthy |
| pid, target_pid | positive integer, daemon and requested target |
| epoch | nonnegative integer, incremented by reset |
| requested_bpf, attached_bpf | integer bit masks: lsm=1, trace=2, kprobe=4, net=8 |
| bpf_configured | boolean, configuration written to every loaded object's maps |
| kernel_responsive | boolean, fresh GET_STATUS ioctl succeeded |
| kernel_target_pid | nonnegative integer, readback (0 if unavailable) |
| kernel_enforce | boolean, readback; meaningful only if kernel_responsive |
| requested_enforce | boolean, CLI setting and daemon policy state |
| lsm_enforce | boolean if attached, otherwise null |
| events_processed | nonnegative integer, pipeline events in this epoch |
| kernel_dropped | nonnegative integer, kernel lifetime drop counter; meaningful only if responsive |
| bpf_dropped | null, BPF loss is not measured by this prototype |
| evidence_loss_known | boolean, true only if kernel responsive and no BPF groups attached |
| code_integrity_baseline, vdso_baseline, signatures_loaded | booleans, actual daemon initialization results; controllers must check those needed by their study |
| bpf_delivery | boolean, event consumer available for attached groups |
| output_failed | boolean, evidence stream missing or write failed |
| error | optional string, client transport/protocol failure |

Attachment bits reflect successful libbpf attach, not merely load or request.
They are owned for the daemon lifetime; kernel responsiveness and target
liveness are checked per request. Readiness does not prove absence of evidence
loss. In particular BPF loss is unknown: never interpret null as zero.
A successful flush proves local filesystem acknowledgement, not remote storage
or protection against device failure. Human logs remain separate.

## Event schema: `owlbear.event.v1`

One JSON object per line in the exclusive mode-0600 `--events` file, including
pipeline-generated signature/preload/integrity events. Fields:

| Field | Type and meaning |
| --- | --- |
| schema | constant `owlbear.event.v1` |
| epoch | nonnegative integer, reset boundary |
| timestamp_ns | nonnegative integer, CLOCK_MONOTONIC nanoseconds, never wall time |
| type, severity, source | integers from `include/owlbear_events.h` |
| pid, target_pid, sequence | nonnegative integers from the event header |
| comm_hex | exactly 32 lowercase hex characters, all 16 comm bytes |
| payload_hex | exactly 128 lowercase hex characters, all 64 payload bytes |

Hex encoding preserves bounded fields, arbitrary bytes and truncation without
JSON escaping or treating untrusted process names as format strings. Payload
layout is the v1 shared header, native little endian on supported ARM64 Linux;
unknown event types retain their full payload. BPF/daemon sequence values may
be zero; they are not global event identifiers. Parse integers without losing
64-bit precision. Streams append within a run and are not truncated by reset.
