# Validation of the MithrilHook development candidate

## Actually performed locally

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

## Pending final-source evidence

- Genuine MSVC x64 and Win32 Debug/Release CTest execution.
- Genuine shared-library test execution and clang-cl x64 execution.
- Execution of the six precise negative controls under Windows.
- Consumer integration and actual application/game startup, rollback, shutdown
  and unload acceptance.

The prepared GitHub workflow covers seven native build cells plus Linux
portable checks. It has not been pushed or dispatched for this local candidate.
There are 16 registered Windows tests on x64 and 15 on Win32; the x64-specific
RIP relocation fixture is intentionally not registered/built as an x86 test.
The bounded thread-churn fixture uses 50 transactions per run.

## Inherited reference evidence

The pinned SAFE-FREEZE predecessor has native verification documented at
https://github.com/cyanoleon/minhook/actions/runs/43374271934.
The Citrine #363 source has focused Debug/Release 19/19 results at
https://github.com/raleonys/citrine-eclipse-mirage/actions/runs/43391349173.
These are reference results for their own source bytes. They do not validate
MithrilHook's renamed API, strict-only source, new alignment/reentry checks or
its final binaries. Read SAFETY.md for the remaining engineering boundaries.
