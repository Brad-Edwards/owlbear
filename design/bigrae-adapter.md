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
