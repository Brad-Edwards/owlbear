# Live BigRAE ARM64 qualification boundary

Issue #34 qualifies a released Owlbear artifact and the independent BigRAE
adapter on an authorized disposable range. Artifact verification, worker/fixture
integration, live qualification and paper study results remain separate claims.
This note supplements [the adapter boundary](bigrae-adapter.md) and
[experiment interface v1](experiment-interface.md); it defines no new runtime
API or implementation sequence. There are no repository ADRs to supersede.

## Ownership and validation boundaries

BigRAE core owns pack admission, authorization, realization, guest transport and
range destruction. The adapter owns only SDK-generated configuration and
readiness actions. The qualification caller owns the target, attack checks and
evidence collection. No cloud credentials, attacks, study logic or infrastructure
lifecycle enter the adapter. No platform internals are copied into this repo.

| Layer | Required incumbent and guardrail |
| --- | --- |
| Range and pack admission | Use the installed BigRAE public pack/configuration validators and authorized range workflow. No pack or core controller is present in this repository: upstream field names, credential binding and teardown receipts must be verified against that installation, not invented here. Preserve active experiments; existing Owlbear dev Terraform is not a disposable BigRAE range. Manual AWS changes retain plan review under `deploy/terraform/README.md`. |
| Worker installation and invocation | Reuse `adapters/bigrae/sdk.json`, delivered `image.json`, hash-locked wheels and `manifest()`; preserve the registry manifest digest when relocating an image to an approved registry. Public SDK `PluginManifest`, `RuntimeInput`, `parse_input` and `parse_result` enforce closed shapes, exact bindings, bounded JSON and invocation/phase/input-digest authorization. Worker exit 0 alone is insufficient: result status and later guest execution must succeed. |
| Parameters and environment | Exactly one Linux `guest` binding and one JSON-string `configuration` parameter pass `configuration()` in `adapters/bigrae/src/owlbear_bigrae/__init__.py`. It rejects unknown/duplicate keys, ambiguous types, unsafe release paths and invalid identities, PID or sensor groups. SDK messages are limited to 65,536 input bytes, configuration to 8,192 bytes; use `BIGRAE_PLUGIN_INPUT` through the host's environment binding, not command-line JSON or shell interpolation. Do not add credential/env passthrough or conflicting legacy input aliases. |
| Artifact and privileged guest | Reuse `guest.py` release/module checks and `scripts/research-artifact.py verify`: trusted manifest hash, exact payload bytes/modes/ELF architecture, canonical root-owned release and ancestors, verifier authentication before execution, exact running kernel, loaded GNU module note and running daemon executable. Outer checksums precede extraction; hashes alone do not authenticate the publisher. Keep release contents immutable. Guest root is required; the planning worker stays unprivileged, without network/capabilities, with read-only root and bounded tmpfs/resources. Never borrow integration-only fake sysfs, module loader or ioctl/BPF fixtures. |
| Runtime control and sensing | Use the daemon CLI, `scripts/owlbearctl.py`, `owlbear.control.v1` and `guest.py:verify_health`, not a second health model or ioctl controller. Private owner-only socket directories, new paths, bounded SOCK_SEQPACKET replies/timeouts and exclusive mode-0600 JSONL remain mandatory. `include/owlbear_events.h`, `daemon/experiment.c` and `daemon/bpf_loader.c` own readback, event layouts and every attached object's maps/ring. Do not open a second `/dev/owlbear` event reader and steal records from the daemon. |
| Errors, logging and storage | Retain SDK bounded failure codes and generic guest failure envelopes; never expose parser input echoes, stack traces, credentials or complete environments. Keep control `ok:false`, transport errors, action exit status and timeouts distinct. `owlbearctl.py` may return local exception text in `error`; review it before exporting. Reuse `daemon/log.h` for daemon diagnostics and versioned JSONL/control receipts for evidence. No new exception hierarchy, database, HTTP endpoint or telemetry schema is needed. |

Cloud/SSH/registry credentials remain in the authorized host's existing credential
mechanism, never in worker parameters, process argv, guest scripts or evidence.
Do not read `.env` or secret files. Capture only required host metadata; raw
environment dumps, Terraform state/plans and unrestricted kernel logs are not
qualification attachments. The existing `platform/api/handler.py` API-key and
DynamoDB path is outside this design: qualification needs no telemetry service.
Registry relocation and evidence transfer require an approved destination;
installed tools and the old verifier's default S3 bucket do not grant approval.

## Readiness, outcomes and limitations

- Preserve SDK operation identity across configure/verify/retry, with a fresh
  invocation identity per call. A retry reads the same private
  `/run/owlbear-<operation UUID>` state; it must not replace an incompatible
  daemon. A different target, mode or sensor selection is a fresh trial with
  clean owned state, not a retry or a control `reset`.
- Readiness requires successful execution of the authorized guest action and
  its `owlbear.bigrae.readiness/v1` receipt, including build identity, target,
  actual attachments/configuration/enforcement, all initialization checks,
  healthy output and zero known kernel drops. `health` command success alone
  can report `ready:false`. Check state at trial boundaries as well as startup.
  The receipt is nested build/health evidence, not a new identity authority.
  Health's `lsm_enforce` reflects the daemon setting and `bpf_configured` reports
  successful map writes; neither independently proves live enforcement. Retain
  read-only inspection of the owned BPF programs/links/maps and kernel probe
  registration, with behavioral checks. Kernel memory probes can fail non-fatally
  even when the module loads. Do not add another sensor configuration path.
- Admit native ARM64, the artifact's exact kernel/ABI/configuration and compatible
  userspace libraries/tools. Record realized OS/image, kernel config/BTF and
  module signing/lockdown policy, available kprobes/BPF hooks, active BPF LSM,
  CPU features, Yama/other LSM policy, seccomp, UIDs/capabilities and target
  ancestry that affect the selected checks. Missing features are unsupported
  coverage, never a reason to silently weaken readiness or rewrite the release.
- A **baseline** without Owlbear is different from **observe** mode, which still
  senses but disables Owlbear denials. Use explicit separate baseline/protected
  state and equivalent attack privileges, target relationship and host policy.
  Restart target/daemon/module between independent trials, or use fresh guests;
  reset only advances the evidence epoch and clears selected counters. Only one
  daemon controls a module. The game uses global `/tmp/owlbear-game.info`, so
  serialize targets on a disposable guest, reject stale/symlink state and bind
  PID/address to the actual caller-owned process; do not trust discovery alone.
- Reuse the released `cheats/` fixtures and `scripts/verify.sh` evidence/check
  conventions. The existing script also unloads modules, starts its own daemon,
  builds missing binaries and accepts some log-only assertions. Its current
  whole-run success cannot qualify the adapter. Keep the protected run under
  adapter-owned readiness; any harness lifecycle seam belongs outside the
  adapter, and any harness revision is separately pinned without modifying
  the selected release or forking the sensor/verifier logic.
- Separate sensor detection, policy intent, actual denial and attack effect.
  `daemon/event_pipeline.c`'s `OWL_ACT_BLOCK` branch logs/counts intent; it cannot
  retroactively deny a syscall. Authoritative outcomes require the fixture's
  syscall return/errno or independent target-state/effect observation, alongside
  Owlbear evidence. Baseline must establish that the same attack can succeed;
  Yama, another LSM, missing devices, invalid addresses, timeout, crash or launch
  failure do not prove Owlbear blocking. Killing after an effect is not prevention.
- `strace` uses ptrace and changes the experiment; avoid tracer conflicts with
  ptrace fixtures and record instrumentation. Separate-process preload/speed/
  network fixtures may not act on the bound target or appear in protected maps.
  `net_exfil` uses a fixed UDP destination; only run it with an authorized isolated
  sink/routing, and do not interpret successful `sendto` as remote receipt.
  Do not change protected maps or allowlist the attacker to manufacture a pass.
- Keep BPF loss unknown (`bpf_dropped:null`), retain kernel lifetime drops and
  bound claims to observed coverage. No events does not prove no attack.
  Event timestamps are guest monotonic nanoseconds; sequence values are not
  global IDs. Preserve epochs/clock domains and integer precision when joining
  evidence. Flush acknowledges bounded local draining/fsync, not a producer
  barrier, remote persistence or all producers having stopped.

## Qualification record and teardown

Use existing BigRAE run/check receipts where available and reference their
identities rather than duplicating their schemas. A small qualification index
may bind those receipts to Owlbear artifacts; it must preserve these facts:

- Selected pack digest/revision, BigRAE version/revision, range/node identity,
  operation/invocation/action identities, SDK and adapter wheel hashes/versions,
  exact installation declaration and worker registry digest. An image ID, tag,
  archive hash and registry manifest digest are different identities.
- Owlbear release source/version/build ID, archive and trusted manifest hashes,
  payload verification, loaded module GNU note and running daemon identity;
  selected guest image and realized OS/kernel/configuration/capabilities.
  A module GNU build note is not the Owlbear build ID or ioctl version.
- Pinned qualification harness/check revision, selected checks and expected
  outcomes, baseline/protected configuration and target identity, timestamps,
  raw guest exit/readiness/control/flush receipts, independent attack results,
  event/log references with SHA-256 hashes, failures, unsupported checks and
  remaining limits. Missing or malformed evidence fails its claim; skipped
  prerequisites and unknown results never become passes or vanish in totals.

Qualification success requires verified readiness, authoritative results for
the required baseline/protected checks, retained evidence and verified teardown.
Unsupported checks bound the claim; they cannot silently replace required checks
or justify lowering the declared sensor selection to obtain a green result.

Keep raw evidence in a private run directory separate from study data and the
immutable release. Retain failures and collect necessary evidence before guest
destruction using the authorized range transport/storage. Hash the finalized
files; make redactions identifiable with their own hashes. A record must not
reference evidence that exists only on a guest that has been destroyed.

BigRAE core destroys only the range/resources owned by this qualification,
including failure/cancellation paths. The adapter's empty cleanup plan and a
successful destroy request are not proof: retain authoritative terminal
destruction status and absence of the owned resources, or record teardown as
failed/unknown with residual resource identities. For guest-level stopping,
use the existing control flush/stop acknowledgements and verify process exit;
never force-unload a module or terminate unrelated processes. Teardown results
remain distinct from readiness and check results.

## Extensibility and non-goals

Keep release identities, exact guest image/kernel, sensor selection, enforcement,
target binding, check selection and evidence destination as caller/pack inputs
validated by their existing owners. An additional supported kernel or release
selects a new pinned artifact and records new evidence; it does not edit a
canonical release or relax validators. Check expectations belong with the
qualification checks, not in adapter configuration or the event schema.

No cloud controller, custom SDK/pack schema, new health/event protocol, release
rebuild/publication, Terraform apply, production-registry upload, platform API
change, paper dataset or broader sensor/enforcement redesign belongs to this
preflight. CI's installed-wheel/worker/explicit guest-fixture checks remain
integration evidence; full suites/builds stay in CI and live qualification
requires the authorized disposable ARM64 range. Tests of any later result
aggregation must reject missing evidence, false blocking claims and teardown
failures, including a deliberate mutation of a success predicate.

## Authorized GCP implementation

The selected implementation uses a disposable C4A ARM64 guest and the existing GCP BigRAE tenant.
The operator has authorized test deployment and isolated worktrees across the affected repositories.
GCP image preparation builds Owlbear for the selected kernel; the earlier generic kernel does not constrain this build.
The caller owns the workload PID file and baseline/protected checks.
Adapter 0.2.0 binds the realized PID to its process start time before configuration.
The worker image uses the control-plane CPU architecture independently of the ARM64 guest.
BigRAE's administrator image binding selects gVNIC, NVMe, Hyperdisk, and the guest module-loading policy.
Control-plane boot policy and existing ranges remain unchanged.

References:

- [Google ARM compute](https://docs.cloud.google.com/compute/docs/instances/arm-on-compute), C4A requirements, current documentation.
- [GCP reference architecture](https://docs.cloud.google.com/architecture/security-foundations), identity and network boundaries, current documentation.
- [Canonical GCP kernels](https://ubuntu.com/gcp/docs/google-how-to/gce/arm64-on-google-cloud/), selected kernel variants, current documentation.

Existing authorization checks and immutable SDK contracts provide policy enforcement.
The image preparation script provides the guest architecture configuration.
No new ADR or duplicate authorization service is required.
The prose and diagrams were reviewed for purpose, short sentences, and consistent technical terms.
