# MithrilHook validation

## Latest merged runtime source

PR #4 was merged as `d32fd189f1459e6f7b70002d1483ada78342f055`.
Its [master run 43456198204](https://github.com/raleonys/mithrilhook/actions/runs/43456198204)
completed successfully in all eight jobs. The reviewed PR head
`e5ac0eff32408557830526de66a5dbe48e11bc7b` also passed
[run 43454757280](https://github.com/raleonys/mithrilhook/actions/runs/43454757280).
The two revisions have identical repository trees. Later documentation changes
do not give these runs a new source identity; use their exact revisions when
citing the results.

| Configuration | Native CTest executions | Result |
| --- | ---: | --- |
| MSVC x64 Debug static | 23 | PASS |
| MSVC x64 Release static | 23 | PASS |
| MSVC x64 Release shared | 23 | PASS |
| clang-cl x64 Release static | 23 | PASS |
| MSVC Win32 Debug static | 18 | PASS |
| MSVC Win32 Release static | 18 | PASS |
| MSVC Win32 Release shared | 18 | PASS |
| Linux portable Debug ASan/UBSan | 2 portable tests | PASS |

This is 146 native test executions plus two portable tests. Nine precise
negative controls apply to x64, eight to Win32. The genuine thread-churn fixture
uses 50 transactions per run. Shared-library verification checks exactly 13
public MTH exports and the MithrilHook product resource.

The MSVC x64 Release artifact for the reviewed PR head records 139 genuine
runtime-function/virtual-unwind checks and 290 registry/retirement failure
checks. The latter use native registry APIs with projected peer scheduling;
they are not 290 independent real-thread schedules. Owned assembly source and
trampoline calls execute, including enable/detour/original/disable behavior.
See [Unwind support](UNWIND.md) for the supported metadata subset.

All seven native configurations accept create/remove for the eleven observed
Windows API targets. The current production target probe fails if any is
refused. It does not enable those hooks or execute those Windows targets.
This result is distinct from actual eleven-hook application acceptance.

## What these checks do not establish

- Comparative performance cannot be inferred from these correctness runs.
  The separate native suite records source-specific timing/compatibility
  artifacts; test durations and the guard-removal support comparison are not
  benchmarks. See [Benchmarks](BENCHMARKS.md).
- Citrine/game startup, live hook behavior, rollback, shutdown or DLL unload
  acceptance with MithrilHook integrated.
- Execution across every Windows release/build or target CPU. Current native
  CI runs on `windows-2022`; changing Windows API prologues can change support.
- General handler-scope translation, arbitrary unwind/ISA support, a universal
  thread-birth barrier or all-or-nothing multi-hook writes. These boundaries
  remain documented in [Safety](SAFETY.md).

Outstanding acceptance work and optional extensions are tracked in
[Remaining work](REMAINING_WORK.md). No stable release has been published.

## Reviewed branch and byte-alias corrections

PR #9 head `614be3d3f1971e508798be21badc5681d391a99a` passed
[run 43463874300](https://github.com/raleonys/mithrilhook/actions/runs/43463874300):
24 tests per x64 cell and 19 per Win32 cell, 153 native executions plus two
portable sanitizer tests. Its linked prefix fixture rejects ambiguous relocated
near CALL/JMP/Jcc forms without changing output/target bytes, permits an
unrelocated prefixed instruction, and executes an ordinary branch control through
source/trampoline/detour/disable/retirement. The actual relocator fixture covers
3,024 byte-alias combinations plus a word-register control. This addresses the
confirmed findings in review PRs #7/#8; their documentation merges alone do not
change runtime behavior. Owner merge/release remains separate.

The subsequent benchmark candidate adds a fresh installed-package consumer in
each native cell. Its seven additional native CTest executions bring that
candidate's total to 160 (153 engine + seven package consumers), plus two
portable tests. This independent find_package/link/runtime check covers Debug/
Release, static/shared, x64/Win32 and clang-cl without Citrine integration; its
own exact-head CI must pass before claiming package acceptance.

Native performance, source-form compatibility and actual-API observations are
recorded by the independent [benchmark workflow](https://github.com/raleonys/mithrilhook/actions/workflows/benchmarks.yml),
for its own exact source revision. Those source manifests and receipts must not
be reassigned to this earlier PR #9 validation run or to another benchmark head.

## Historical stages

| Stage | Source/run | Evidence and boundary |
| --- | --- | --- |
| Initial local core | `metadata/LOCAL_VALIDATION.json` | Portable Debug/Release 2/2, x64/x86 cross-builds and 13-export PE checks. Its original native/publication PENDING fields are a historical snapshot, not current status. |
| Core and branding predecessor | `742d6a7685a6c8c71f8210d8ea35f731e2864b28`, [43434695722](https://github.com/raleonys/mithrilhook/actions/runs/43434695722) | 109 native executions plus two portable tests; six precise Windows negative controls. |
| Refusal-only thread/batch/unwind audit | `00c5f9a7cc4bfed1517a43e9dd9df9d8eaef2b93`, [43441584117](https://github.com/raleonys/mithrilhook/actions/runs/43441584117) | 138 native executions plus two portable tests, but only 3/11 x64 targets accepted; Win32 11/11. That stage was not ready for eleven-hook integration. |
| Owned-unwind follow-up | `e5ac0eff32408557830526de66a5dbe48e11bc7b`, [43454757280](https://github.com/raleonys/mithrilhook/actions/runs/43454757280) | 146 native executions plus two portable tests; x64/Win32 create/remove 11/11. Same tree as the merged runtime source above. |

The initial local UBSan run detected unaligned decoder accesses. The corrected
HDE reads and relocation displacement stores use memcpy, with undefined
behavior configured to stop the sanitizer tests. Portable execution projects
Windows memory-query/protection boundaries; it does not execute native Windows
suspension. Cross-compilation is a build result, not Windows execution.

## Inherited reference evidence

The pinned SAFE-FREEZE predecessor has native verification in
[cyanoleon run 43374271934](https://github.com/cyanoleon/minhook/actions/runs/43374271934).
Citrine #363 has focused Debug/Release 19/19 results in
[run 43391349173](https://github.com/raleonys/citrine-eclipse-mirage/actions/runs/43391349173).
These runs validate their own recorded source bytes, not later MithrilHook
sources or binaries. Historical evidence is retained without rewriting its
original hashes or pending fields.
