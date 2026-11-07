# Prepare a GCP qualification guest

Use a disposable native ARM64 Compute Engine VM with Ubuntu 24.04.
C4A requires gVNIC and Hyperdisk storage.
Run `sudo bash prepare-image.sh COMMIT` with a full reviewed Owlbear commit.
The script refuses an existing installation.
It builds the immutable release against the running kernel and records all build inputs.
It enables BPF LSM for the next boot without removing the configured LSM order.
Reboot the disposable guest before qualification.
Verify `bpf` in `/sys/kernel/security/lsm` and retain the exact kernel release.

The current release module is unsigned.
The administrator-selected research guest must permit its loading.
Select that boot policy explicitly; preserve vTPM and integrity monitoring.
Do not change the control plane or existing range boot policy.

Capture a clean, stopped guest as an immutable ARM64 image.
The preparation script installs the workload units but leaves them disabled.
After the verification reboot, enable them without starting a trial:

```sh
sudo test ! -e /var/lib/owlbear-qualification/baseline.json
sudo test ! -e /var/lib/owlbear-qualification/baseline-game.log
sudo systemctl enable owlbear-qualification-target.service
```

If you ran a builder trial, retain its evidence separately and remove its owned baseline state before capture.
Stop its daemon and target, unload its module normally, and verify their absence first.
Never copy a completed baseline into the image.
Clean cloud-init instance state and SSH host keys through the provider image preparation procedure.
Stop the builder before capture; each realized guest must run its own fresh baseline.
Keep the artifact archive, external manifest, and checksums with the qualification evidence.
The image contains build outputs, not a successful experiment.
Register its exact image identity and hardware settings through BigRAE administration.
The runtime adapter selects `/opt/owlbear/releases/qualification` and never downloads software.

[Google ARM compute](https://docs.cloud.google.com/compute/docs/instances/arm-on-compute)
describes provider requirements.
[Canonical kernel guidance](https://ubuntu.com/gcp/docs/google-how-to/gce/arm64-on-google-cloud/)
describes GCP kernel variants.

The caller-owned systemd units run a fresh baseline target before the protected target.
The baseline target exits before the protected target starts.
The PID file names the protected target and is available only to root.
The memory checker records syscall return values and errno independently of daemon events.
Baseline requires successful reads, writes, and ptrace attachment.
Protected checks require EPERM for every selected operation; other errors fail qualification.
Retain health and flush receipts before stopping the daemon and destroying the range.

The [BigRAE GCP qualification record](../../qualification/bigrae/records/2026-11-07-gcp-bigrae.md)
lists the tested image hardware, pinned builds, observed results, and verified teardown.
