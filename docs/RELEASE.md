# Release preparation

VERSION contains 1.0.0-rc.1. CMake and Windows fixed numeric metadata use 1.0.0;
package/DLL strings preserve the full candidate version and Windows resources
set the prerelease flag. This preparation does not create a tag or publish a
release. The owner controls publication.

## Candidate contents and evidence

The candidate contains the independent thirteen-export MTH API, strict
ownership core, bounded generated unwind support and reviewed corrections
through the PUSH range fix in PR #17. The [changelog](../CHANGELOG.md) groups
user-visible behavior and links the implementation PRs. Historical report-only
PRs and the old 0.1.0 development identifier are not prior stable releases.

Use the exact committed candidate head for native correctness, installed-package
validation and the five-environment benchmark. The candidate PR records run
links; each benchmark artifact records its commit, source/input manifests,
binary receipts, raw streams, checksums, compatibility and audit results.
Earlier source-specific numbers remain valid only for those earlier sources.

Validation artifacts are named with the full candidate version and contain the
installed static/shared Debug/Release packages, native test logs, installed
consumer logs, licenses, VERSION and changelog. Inspect source/provenance and
all relevant checks before choosing publication assets. Artifact retention is
finite; preserve selected source/raw-evidence archives with the release record.

The distribution remains GPL-3.0-only, with MinHook/HDE BSD and authorized
SAFE-FREEZE notices retained. No BSD relicensing is performed by this PR.

## Consuming the candidate

An unversioned find_package(MithrilHook CONFIG REQUIRED) discovers the explicitly
selected installed package. To use a numeric 1.x request with this candidate:

```cmake
set(MithrilHook_ALLOW_PRERELEASE ON)
find_package(MithrilHook 1.0 CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE MithrilHook::mithrilhook)
```

Without that consent a numeric version request refuses prerelease packages;
CMake's numeric syntax cannot express an rc suffix. The imported configuration
exposes MithrilHook_VERSION, MithrilHook_VERSION_NUMERIC and
MithrilHook_PRERELEASE. Match the package's static/shared and Debug/Release CRT
configuration. This does not add a runtime dependency or legacy API alias.

## Publication and the following integration

After the candidate's library correctness/package/performance gates are
reviewed, the owner can select the release version and immutable tag. A stable
1.0.0 requires changing VERSION to 1.0.0, updating its changelog entry and
validating those final assets; rc evidence must keep its recorded identity.
Citrine then integrates the chosen package deliberately. Actual host/API/game
startup, live callbacks, error recovery, shutdown and unload acceptance remain
that next phase. See [Remaining work](REMAINING_WORK.md).
