# BigRAE adapter boundary

The independent `owlbear-bigrae-adapter` wheel depends only on the public
`bigrae-adapter-sdk[runtime]` contract and standard library. It registers one
factory in `bigrae.runtime.plugins`. SDK plans authorize one Linux guest;
configuration selects an already staged release under /opt/owlbear/releases.
It never fetches releases, creates infrastructure, or accesses cloud credentials.

Flow: RuntimeInput -> closed configuration -> bounded GuestAction -> existing
artifact verifier, module loader, daemon CLI -> control socket readback.
Verification checks artifact identity and bytes, running kernel/architecture,
loaded module GNU build note, daemon executable and runtime readback. Only guest
execution exit status proves readiness; a planned action does not.

Each operation has its own private /run/owlbear-<operation UUID> directory.
Existing healthy state is read back on retry; incompatible state fails rather
than being killed/replaced. Core owns guest destruction and cleanup. No study,
attack, policy adaptation, or evidence upload belongs here.

Image selection uses SDK PluginManifest validation: exact registry digest,
distribution version and entry point. Image construction consumes a complete
hash-locked wheelhouse, without fetching packages. No fabricated image digest
or publication claim is committed. Tests install built SDK/adapter wheels in a
separate environment and exercise the actual worker; guest predicates have
negative tests and a deliberate mutation check.

## Completed delivery and integration boundary

Consume the already published upstream CI SDK wheel by artifact ID and SHA-256,
including its MIT license; do not rebuild it or require a new PyPI release.
`release.py` creates a hash-locked wheelhouse, worker image, real registry
manifest identity and portable image archive. A disposable loopback registry
exists only for the integration test. CI retains the archive, exact SDK and
adapter wheels, installation declaration, hashes and test receipts through the
repository's existing artifact service. No production registry or tenant is used.

The production worker runs with no network, no capabilities, UID 65532, read-only
root and bounded tmpfs. Guest integration runs on native ARM64 in a separate
container, using the real daemon linked to the existing explicit ioctl/BPF
fixture. Only the guest test has private writable fake sysfs and a fake module
loader. It never mounts host sysfs or loads a real module. Configure, retry,
verify and negative readbacks execute complete SDK-generated guest scripts.
The guest fixture cannot enter the worker image or runtime package.
