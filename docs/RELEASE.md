# Release preparation

The selected distribution version is **1.0.1**. VERSION is canonical. CMake,
installed packages and Windows file/product resources all use 1.0.1, without
an RC suffix. DLL resources clear the prerelease flag. Setting this version
does not itself create a GitHub release or tag; the owner controls publication.

## Contents and evidence

The library includes the independent thirteen-export MTH API, strict ownership
core, bounded generated unwind support and reviewed corrections through the
x87 FIP/state-save policy in PR #19. The [changelog](../CHANGELOG.md) groups
current behavior and links implementation PRs. The earlier 0.1.0 and
1.0.0-rc.1 development identifiers are not listed as prior stable releases.

Use the exact committed source for correctness, installed-package verification
and comparative performance. PR #19 records its fresh Windows/package checks;
older benchmark records retain their measured source/versions and are not
renamed to 1.0.1. Benchmark artifacts record commits, manifests, executable
receipts, raw samples, checksums, compatibility and audit results.

Versioned validation artifacts contain installed static/shared Debug/Release
packages, native/consumer test logs, licenses, VERSION and the current changelog.
Before publication inspect source provenance, thirteen exports, full/fixed
1.0.1 resources and a clear prerelease flag. Preserve chosen source/evidence
archives because workflow artifact retention is finite.

Distribution remains GPL-3.0-only, with original MinHook/HDE BSD and authorized
SAFE-FREEZE notices retained. No relicensing is part of this work.

## Consuming 1.0.1

An unversioned package request remains available. Numeric stable requests need
no prerelease permission:

```cmake
find_package(MithrilHook 1.0.1 EXACT CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE MithrilHook::mithrilhook)
```

The package exposes MithrilHook_VERSION=1.0.1,
MithrilHook_VERSION_NUMERIC=1.0.1 and an empty MithrilHook_PRERELEASE. Independent
consumers verify exact 1.0.1 and compatible 1.0 discovery with prerelease consent
disabled, reject incompatible major versions, then link and run. Match the
package's static/shared and Debug/Release CRT settings. There is no additional
runtime dependency or legacy API alias.

## Publication and the following integration

After reviewing the selected source's correctness, package, performance and
source/license evidence, the owner selects the immutable tag and assets.
Citrine then integrates that package deliberately. Actual target prologues,
startup, callbacks, recovery, shutdown and DLL unload remain the following
application acceptance phase. See [Remaining work](REMAINING_WORK.md).
