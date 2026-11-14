# MithrilHook 1.0.5 stable release

The selected distribution version is **1.0.5**. [VERSION](../VERSION) is canonical.
CMake, installed package metadata and DLL file/product resources use 1.0.5
without an RC suffix or prerelease opt-in. The DLL prerelease flag is clear.
The owner plans stable **v1.0.5** publication after PR #25 is integrated and
its exact-source validation and package evidence are reviewed. This source
change does not itself publish a tag, GitHub release or binary asset.

The existing [v1.0.4 release and downloads](https://github.com/raleonys/mithrilhook/releases/tag/v1.0.4)
remain available with their original source, checksums and evidence.

## Packages and source

The 1.0.5 publication plan retains these Windows x86/x64 package configurations:

| Architecture | Compiler | Configuration | Library |
| --- | --- | --- | --- |
| x64 | MSVC v143 | Debug | Static |
| x64 | MSVC v143 | Release | Static |
| x64 | MSVC v143 | Release | Shared |
| x64 | clang-cl | Release | Static |
| x86 | MSVC v143 | Debug | Static |
| x86 | MSVC v143 | Release | Static |
| x86 | MSVC v143 | Release | Shared |

Packages include the public header, library/import library and DLL as applicable,
CMake package files, VERSION, installed usage/safety/unwind/branding documentation,
the exact approved logo and distribution/upstream license notices. The installed
`share/mithrilhook/doc` directory preserves the repository-relative `docs/` and
`metadata/` tree so changelog and guide links resolve inside the package. Match each
package's architecture, configuration and CRT settings; MSVC defaults to /MT or
/MTd. Compiler-provided CRT support is used normally. MithrilHook introduces no
external decoder, NT-header package or dependency on the application repository.

`MithrilHook-1.0.5-source.tar.gz` must contain the exact accepted source selected
for the v1.0.5 tag. This patch adds explicit page-offset and diagnostic types
while retaining the reviewed 1.0.4 algorithms, ownership rules and thirteen
exports. Earlier 0.1.0, 1.0.0-rc.1 and prepared 1.0.1/1.0.2/1.0.3 identifiers
were development versions; v1.0.4 was the first public stable release.
Distribution remains GPL-3.0-only with original MinHook/HDE and separately
authorized SAFE-FREEZE notices preserved.

## Verification and evidence

Before publication, bind SHA256SUMS, the source archive, all seven installed
packages and `MithrilHook-1.0.5-VALIDATION.json` to the same accepted release
commit/tree and version 1.0.5. Review the complete native matrix, installed
consumers, shared-DLL resource checks, portable sanitizers and both 250-process
shared live-call stress runs. A failed stress process remains a release blocker;
an unrelated passing rerun alone does not explain that failure.

Retain the exact-source benchmark run, raw environment ZIPs, independent audits
and readable report with their actual measured source/version. Historical
[v1.0.4 validation](https://github.com/raleonys/mithrilhook/releases/download/v1.0.4/MithrilHook-1.0.4-VALIDATION.json)
and benchmark assets remain evidence for 1.0.4 only. New 1.0.5 assets and
measurements are not claimed until they have been generated and checked.

## Consuming 1.0.5

```cmake
find_package(MithrilHook 1.0.5 EXACT CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE MithrilHook::mithrilhook)
```

The package exposes MithrilHook_VERSION=1.0.5,
MithrilHook_VERSION_NUMERIC=1.0.5 and an empty MithrilHook_PRERELEASE. Independent
consumers require exact 1.0.5 and compatible 1.0 discovery with prerelease consent
disabled, reject major 2, then link and execute the installed library.
The independent API has thirteen MTH exports and no legacy aliases.

## Following integration

Library release evidence is separate from application acceptance. Laureondo
currently pins the owner-supplied vanilla MithrilHook 1.0.4 archive. Importing a
new immutable package is a separate reviewed step with new archive/member pins
and application validation; PR #25 does not silently change that input.
Integration must validate actual target prologues, startup, detour/original calls,
failure recovery, callback admission/draining, shutdown and DLL unload on the
identified deployment environment. See [Integration status](REMAINING_WORK.md),
[API](API.md), [Safety](SAFETY.md) and [Unwind support](UNWIND.md).
