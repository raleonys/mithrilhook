# Validation of the MithrilHook development candidate

## Initial recorded local verification

The following describes the initial core candidate recorded in
metadata/LOCAL_VALIDATION.json, before the current audit changes. Its source
hashes and original pending/publication fields are retained as historical
evidence, not represented as the current repository status.

- Source/export/branding inventory verification and whitespace checks.
- GCC 14.2 x64 portable Debug build with AddressSanitizer and
  UndefinedBehaviorSanitizer, with UBSAN_OPTIONS=halt_on_error=1: 2/2 CTest
  cases passed. The actual decoder passed 112 checks across byte alignments;
  the actual relocator passed 11 checked-relocation/boundary assertions.
- GCC 14.2 x64 portable Release: 2/2 CTest cases passed.
- Zig 0.14.1 / Clang 19.1.7 Windows x64 and x86 Release cross-builds: static
  library and all configured native test targets compiled and linked. The
  final build logs contain zero compiler warnings and errors.
- Windows x64 and x86 Release shared-library cross-builds: compiled/linked.
  Independent PE parsing verified exactly 13 MTH exports, no extra ordinal
  exports, and the MithrilHook product resource in both DLLs.
- Six exact-failure control sources were generated from the pinned engine:
  create/remove/enable/queue/apply cleanup barriers and stale disable action.
  Their binaries cross-built; their Windows execution is still pending.

The portable tests project only Windows memory-query/protection boundaries.
They do not execute native Windows suspension or callbacks. Cross-compilation
is a build result, not Windows execution. No Wine/native/game PASS is inferred.

An initial UBSan run detected misaligned multi-byte decoder loads. The modified
HDE reads and relocation displacement stores now use memcpy. The same test
passes with undefined-behavior failures configured to stop execution.

## Accepted predecessor native evidence

Master 742d6a7685a6c8c71f8210d8ea35f731e2864b28 passed all seven native Windows
configurations and Linux portable checks:
https://github.com/raleonys/mithrilhook/actions/runs/43434695722.
That run executed 109 native tests (16 per x64 configuration and 15 per Win32
configuration), plus two portable tests. The original six precise negative
controls executed under Windows; the prior local-only pending statements above
describe their earlier verification stage.

## Current audit candidate

The thread/batch/unwind audit is described in SECURITY_AUDIT.md. The workflow
covers MSVC x64/Win32 Debug/Release static, x64/Win32 Release shared and clang-cl
x64 Release, plus Linux portable ASan/UBSan checks. There are 23 native tests on
x64 and 18 on Win32: 146 executions across the seven cells. X64-only relocation
and runtime-function/unwind fixtures are not claimed as Win32 execution. Nine
precise negative controls apply to x64, eight to Win32. The bounded genuine
thread-churn fixture uses 50 transactions per run.

Cross-builds and source checks do not establish native acceptance for these new
bytes. Use the exact candidate head's checks at
https://github.com/raleonys/mithrilhook/actions/workflows/validation.yml.
Consumer integration and actual application/game startup, rollback, shutdown
and unload acceptance remain separate work.

The current target probe requires all eleven pinned-runner create/remove
classifications to succeed; a refusal fails its CTest case. This stronger gate
does not turn create/remove into API execution or application acceptance.

## Inherited reference evidence

The pinned SAFE-FREEZE predecessor has native verification documented at
https://github.com/cyanoleon/minhook/actions/runs/43374271934.
The Citrine #363 source has focused Debug/Release 19/19 results at
https://github.com/raleonys/citrine-eclipse-mirage/actions/runs/43391349173.
These are reference results for their own source bytes. They do not validate
MithrilHook's renamed API, strict-only source, new alignment/reentry checks or
its final binaries. Read SAFETY.md for the remaining engineering boundaries.
