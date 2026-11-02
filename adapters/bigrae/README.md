# Owlbear BigRAE runtime adapter

Independent wheel `owlbear-bigrae-adapter==0.1.0`, entry point `owlbear` in
`bigrae.runtime.plugins`, using `bigrae-adapter-sdk[runtime]==0.1.0`.
The worker returns SDK plans; BigRAE authorizes targets and executes guest actions.
An installation inspection or successful plan does not prove guest readiness.

## Build and test

Build with `uv build --wheel adapters/bigrae`. Install the SDK and adapter wheels
in a separate environment, then run its Python against `adapters/bigrae/tests`.
Do not add the BigRAE checkout to PYTHONPATH or copy platform code into the worker.

The SDK coordinate is not currently on PyPI. The public SDK
[documentation](https://github.com/OpenRAE/bigrae/blob/9552c9f309eb9a286e5442db44d55ff0f408e19a/shifter/shifter_adapter_sdk/README.md)
permits exact candidate wheels for development. CI builds that pinned public
revision, installs both wheels independently and exercises the SDK worker.
Record the SDK wheel SHA-256 with each image build; a version alone does not
identify a candidate. Local testing used wheel SHA-256
`b61e1e7b7b12bd3726dc8cfb23c0dd4de4d3c4e7ab8704548683355aedd4102a`.
These tests establish candidate compatibility, not SDK publication or live qualification.

For the Dockerfile supply an approved Python >=3.12 base image by registry digest.
Populate `wheelhouse/` with approved wheels and a `requirements.lock` pinning
and hashing every dependency, the SDK and this adapter. Pip installs offline
with `--require-hashes`. Publish only through the existing authorized registry
process, then generate the installation declaration with its resolved digest:

```sh
owlbear-bigrae-manifest --worker-image 'REGISTRY/REPOSITORY@sha256:ACTUAL_DIGEST'
```

Tags and missing digests are rejected. No fabricated deployable digest or registry
publication is included. A deployment is incomplete until the publisher records
the actual image digest and SDK wheel identity. Run with UID/GID 65532, read-only root, network disabled,
and bounded tmpfs `/tmp`, as required by the SDK. Worker architecture is separate
from guest architecture. The worker requires neither root nor cloud credentials.

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
The caller starts and owns the target process. No attack or game behavior is built
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
