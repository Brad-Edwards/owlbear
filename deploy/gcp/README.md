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
Keep the artifact archive, external manifest, and checksums with the qualification evidence.
The image contains build outputs, not a successful experiment.
Register its exact image identity and hardware settings through BigRAE administration.
The runtime adapter selects `/opt/owlbear/releases/qualification` and never downloads software.

[Google ARM compute](https://docs.cloud.google.com/compute/docs/instances/arm-on-compute)
describes provider requirements.
[Canonical kernel guidance](https://ubuntu.com/gcp/docs/google-how-to/gce/arm64-on-google-cloud/)
describes GCP kernel variants.
