# MithrilHook 1.0.4 stable release

The distribution version is **1.0.4**. [VERSION](../VERSION) is canonical.
CMake, installed package metadata and DLL file/product resources use 1.0.4
without an RC suffix or prerelease opt-in. The DLL prerelease flag is clear.
The owner authorized publication of the stable **v1.0.4** tag and release.

[Official release and downloads](https://github.com/raleonys/mithrilhook/releases/tag/v1.0.4)

## Packages and source

The release provides these Windows x86/x64 packages:

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

`MithrilHook-1.0.4-source.tar.gz` contains the exact tagged source. The release
changelog includes all reviewed changes through PR #23. Earlier 0.1.0,
1.0.0-rc.1 and prepared 1.0.1/1.0.2/1.0.3 identifiers were development versions,
not prior public stable releases. Distribution remains GPL-3.0-only with original
MinHook/HDE and separately authorized SAFE-FREEZE notices preserved.

## Verification and evidence

Download SHA256SUMS alongside the selected assets and verify their SHA-256
hashes. The source archive, packages and validation metadata must agree on
version 1.0.4 and the selected release commit.

[Release validation identity](https://github.com/raleonys/mithrilhook/releases/download/v1.0.4/MithrilHook-1.0.4-VALIDATION.json)
records the tag/commit/tree, workflow runs, artifact digests, package source and
binary identities, native/portable results and independent benchmark audits.
The release also retains native logs, raw benchmark ZIPs, the readable benchmark
report, full timing CSV and PNG/PDF comparison. Older measurements retain their
actual commits and versions; they are not relabeled as 1.0.4 results.

## Consuming 1.0.4

```cmake
find_package(MithrilHook 1.0.4 EXACT CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE MithrilHook::mithrilhook)
```

The package exposes MithrilHook_VERSION=1.0.4,
MithrilHook_VERSION_NUMERIC=1.0.4 and an empty MithrilHook_PRERELEASE. Independent
consumers verify exact 1.0.4 and compatible 1.0 discovery with prerelease consent
disabled, reject major 2, then link and execute the installed library.
The independent API has thirteen MTH exports and no legacy aliases.

## Following integration

Library release evidence is separate from application acceptance. Citrine
integration must validate actual target prologues, startup, detour/original calls,
failure recovery, callback admission/draining, shutdown and DLL unload on the
identified deployment environment. See [Integration status](REMAINING_WORK.md),
[API](API.md), [Safety](SAFETY.md) and [Unwind support](UNWIND.md).
