# Experiment interface v1

The existing CLI remains the configuration and process lifecycle interface.
A daemon may additionally bind a Unix socket in a controller-owned private
run directory. A small Python standard-library client sends one versioned
request per connection; replies are JSON. No network service is introduced.

Data flow: controller -> local socket -> daemon event loop -> ioctl / BPF maps.
Sensors -> ring buffers -> daemon pipeline -> JSONL evidence file.
Health reads the kernel status and BPF attachment state; requested groups are
reported separately. Kernel sensing and daemon periodic checks remain enabled;
BPF groups lsm, trace, kprobe, net are selectable. Observe mode must disable
LSM denials too. Each skeleton owns separate maps and an event ring, so every
loaded object must receive configuration and have its ring consumed.

Commands: health, flush, reset, stop. Mode and sensor changes require a new
process, preserving a fixed configuration within each run. Reset clears only
pipeline statistics and process ancestry and increments an evidence epoch;
it never silently replaces integrity baselines or clears loss counters.
Flush drains currently available records with a finite bound, flushes and
fsyncs the evidence stream, then replies. It cannot freeze producers.
Health is also the run manifest: schema version, requested and realized state,
PID, target, epoch, counters, readiness, and known/unknown evidence loss.

Security: private directory, owner-only socket, no path replacement, bounded
requests and timeouts, no shell evaluation. Evidence files are created
exclusively with mode 0600. Socket commands execute serially in the event loop.
Disconnects cannot terminate the daemon. No new external processing/storage.

Exec-event preload inspection must not wait for an exited process.
An absent process cannot become readable through a retry; its PID can be reused.
Return immediately on ENOENT or ESRCH, while preserving retries for transient reads.
This prevents obsolete exec events from delaying control requests.

Invariants checked by targeted tests: v1 replies parse as JSON; malformed
requests fail; sensor masks reject unknown groups; event strings cannot break
JSON; failed writes prevent readiness; flush acknowledges durable local output;
reset preserves configuration and loss. Hardware verification remains in the
existing verifier; local tests use an explicit fake device integration fixture.
