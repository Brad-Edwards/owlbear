# Owlbear BigRAE runtime adapter

Independent wheel `owlbear-bigrae-adapter==0.2.0`, entry point `owlbear` in
`bigrae.runtime.plugins`, using `bigrae-adapter-sdk[runtime]==0.1.0`.
The worker returns SDK plans; BigRAE authorizes targets and executes guest actions.
An installation inspection or successful plan does not prove guest readiness.

## Build and test

Build with `uv build --wheel adapters/bigrae`. Install the SDK and adapter wheels
in a separate environment, then run its Python against `adapters/bigrae/tests`.
Do not add the BigRAE checkout to PYTHONPATH or copy platform code into the worker.

## Complete worker delivery

The adapter consumes the SDK's **published CI distribution**, the route supported
by the upstream SDK for independent adapters. `sdk.json` records the upstream
repository, artifact ID, run, revision, ZIP hash and wheel hash. The exact 33 KB
MIT-licensed SDK wheel is preserved under `vendor/`, including its license, so
expiration of an upstream CI download cannot change or break this release.
There is no dependency on an unpublished PyPI coordinate or a mutable checkout.

```sh
python3 adapters/bigrae/release.py --output /absolute/new/release-directory --guest-integration
```

The complete integration run requires native ARM64, Docker, `skopeo` and `uv`. Omit
`--guest-integration` for local worker tests on x86; CI runs the full ARM64 path.
The script verifies the SDK hash, builds the adapter wheel, resolves the exact
versions in `constraints.txt` into a hash-locked wheelhouse for Python 3.12, and
builds the worker from the pinned multi-architecture Python image. The Dockerfile
installs all wheels offline using `--require-hashes`.

A disposable **loopback-only local registry** provides the worker's real registry
manifest digest. The script pushes and pulls that exact identity, tests it under
BigRAE's restrictions, and verifies the exported archive contains the same manifest
and intact blobs. No external registry, cloud provider or BigRAE tenant is used.
The registry container is removed even after a test failure.

The release directory and the CI artifact `owlbear-bigrae-worker-arm64` contain:

- `worker.tar`: standard containers/image directory transport archive, with its registry manifest preserved.
- `image.json`: registry digest, image identity, architecture, base image and SDK identity.
- SDK, adapter and dependency wheels, plus `requirements.lock` and `SHA256SUMS`.
- `worker-integration.json` and `guest-integration.json`: authoritative test receipts.
- `integration-installation.json`: the exact SDK installation declaration tested.

The installation declaration's loopback address belongs to the disposable test
registry. To install later, extract the archive and use `skopeo copy --all --preserve-digests
dir:/extracted/image docker://AUTHORIZED_REGISTRY/REPOSITORY:VERSION` without
changing its manifest and generate the declaration with that registry and the
recorded digest. The registry name may change; the digest must match `image.json`:

```sh
owlbear-bigrae-manifest --worker-image 'AUTHORIZED_REGISTRY/REPOSITORY@sha256:RECORDED_DIGEST'
```

This is artifact delivery and integration qualification, not live-tenant deployment.
The worker runs with UID/GID 65532, no network, no capabilities, read-only root,
bounded memory/PIDs and a bounded `/tmp` tmpfs. All five SDK phases execute from
the actual digest; the test also checks that platform modules are absent.

The separate ARM64 guest test executes complete generated configure/verify scripts
against the real daemon linked to the repository's explicit fake ioctl/BPF fixture.
Its module-loader fixture writes a build note into **private tmpfs sysfs**, never
host sysfs. The test container alone enables SYS_PTRACE and removes AppArmor's
sysfs restriction for this fake filesystem. It loads no real kernel module.
Configuration, idempotent retry, verification, wrong-release and wrong-enforcement
readback, and artifact tampering are checked. This fixture cannot enter the worker
image or adapter wheel. Live sensor/attack qualification remains issue #34 and is
outside these integration tests.

## Configuration

Bind exactly one Linux node as `guest`. Provide one `configuration` parameter,
a JSON string with these exact fields (replace all illustrative identities):

```json
{
  "release": "/opt/owlbear/releases/release-directory",
  "manifest_sha256": "64 lowercase SHA-256 hex characters",
  "build_id": "64 lowercase SHA-256 hex characters",
  "version": "2.5.0",
  "source_commit": "40 lowercase git commit hex characters",
  "kernel_release": "6.17.0-exact-guest-kernel",
  "target_pid": 123,
  "sensors": ["lsm", "trace", "kprobe", "net"],
  "enforce": true
}
```

Configuration **selects** a pre-staged extracted release; it performs no downloads
or transfers. All release files and ancestors must be root-owned and not writable
by others. Use a trusted manifest hash from the intended release. The guest needs
ARM64 Linux, the exact kernel, matching libraries, Python 3, kmod (`insmod`),
binutils (`readelf`) and root guest execution. The isolated worker remains unprivileged.
The caller starts and owns the target process.
For a newly realized guest, `target_pid` can instead be a canonical PID-file path
such as `/run/owlbear-qualification/target.pid`. The file and its ancestors must
be root-owned and not writable by other users. The adapter reads a bounded
integer and records the process executable and start time. Retry and verification
refuse a changed process identity, including PID reuse. No attack or game behavior is built
in. Empty `sensors` disables BPF groups; kernel and daemon checks remain active.
Parameters are encoded as JSON data, never interpolated into shell commands.

## Behavior and evidence

`validate` checks the declaration, Linux binding and configuration with no actions.
`configure` authenticates the verifier against the pinned manifest, invokes the
existing artifact verifier, checks embedded build identity and guest kernel, loads
the exact module if absent, then starts the daemon with the declared runtime
parameters. A module already loaded is accepted only if its GNU build note matches
the selected ELF. Guests without readable module build notes fail explicitly.

`verify` repeats identity verification and reads the control socket with a two-second
timeout and bounded output. It checks realized PID, attachments and enforcement,
all three daemon initialization results (signature loading, code-integrity and vDSO
baselines), output health and zero known kernel drops. Unknown BPF loss remains
unknown. The running daemon executable must resolve to the selected release.
Readiness polling has a 15-second deadline; guest actions have a 120-second host
limit and subprocess deadlines. Successful execution prints
`owlbear.bigrae.readiness/v1` with the build identity and actual health response.
The host must use guest exit status, not plan status, as readiness evidence.

State is private to `/run/owlbear-<operation UUID>`, mode 0700. Retries inspect
existing state without replacing processes, sockets or evidence. Incomplete or
incompatible state fails for inspection. Core guest destruction owns cleanup;
the adapter returns no cleanup actions and contains no infrastructure lifecycle,
cloud access, study behavior or evidence upload. Live qualification is issue #34.
