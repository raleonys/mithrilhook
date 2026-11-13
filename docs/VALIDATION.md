# MithrilHook validation

## Release candidate and exact source identity

The unpublished distribution version is 1.0.0-rc.1. The candidate in
[PR #18](https://github.com/raleonys/mithrilhook/pull/18) adds internal-CALL
patch-window refusal to merged PR #17. Its new native results belong to that
PR's exact head. The completed #17 validation and benchmark results retain
their earlier source identity.
A document, tag or version change does not transfer evidence to other bytes.

The candidate matrix contains four x64 cells (MSVC Debug/Release static,
MSVC Release shared and clang-cl Release static) and three Win32 MSVC cells
(Debug/Release static and Release shared). It exercises public API calls,
real owned-code execution, peer/retirement behavior and exact negative controls.
Each cell also builds and executes an independent installed-package consumer.
The portable decoder and relocator run under Linux ASan/UBSan; the relocator
contains 11,790 assertions, including 511 PUSH prefix/range layouts and 1,040
CALL prefix/site/destination layouts plus ten forward-entry/expansion cases.
Internal CALL refusal is checked before output or entry-patch publication.
A generated native negative control removes only that refusal and must exit 1
at the exact refusal assertion before any unsafe original is executed.
Ordinary outside CALL controls execute source/original/detour/restore paths on
both architectures; registered x64 controls verify source v1/generated v2
unwind and actual generated-table retirement. Word-PUSH
range checks are structural; the registered native execution/unwind fixture
uses ABI-describable eight-byte stack allocations.

Versioned package requests do not silently accept a prerelease. Each installed
consumer checks refusal without candidate consent, then explicitly accepts the
candidate and verifies full/numeric package metadata before linking and running.
Shared builds verify thirteen exact exports, product identity, numeric/full
version resources and the prerelease flag against VERSION.

## Completed predecessor evidence

These records validate their pinned sources, not later candidate bytes.

| Stage | Exact source / run | Completed evidence |
| --- | --- | --- |
| Through PR #17 | `f006e53116b61ed9baabec025ed6bb26a7c6c7eb`, [43494694097](https://github.com/raleonys/mithrilhook/actions/runs/43494694097) | 189 native engine tests + seven installed consumers (196 native total), two portable tests; merged as `9f822317bcf3fa52a12683e0fbfaf1e28e3bcaee`. Predates the internal-CALL correction in #18. |
| Through PR #16 | `59c851fd772838a9b84f3df8c202f657f1cec5f8`, [43488613785](https://github.com/raleonys/mithrilhook/actions/runs/43488613785) | 185 native engine tests + seven installed consumers (192 native total), two portable tests; merged master `c02605cb041034c3158abd0f5974f3b564657e71` has the identical tree. |
| RIP access hardening, PR #15 | `ca1de1620b21b9580a48b608667075384fbcfc0a`, [43486839224](https://github.com/raleonys/mithrilhook/actions/runs/43486839224) | 171 native including consumers + two portable; native source/original/detour/restore/retirement and 512-byte access controls. |
| Internal branches, PR #14 | `56c7fb3f0170a3de65b8c3a2eef40a4ce720143a`, [43482234324](https://github.com/raleonys/mithrilhook/actions/runs/43482234324) | 167 native including consumers + two portable; backward JMP/Jcc and LOOP after expansion, mapped boundaries and forward controls. |
| CALL-next / APX refusal, PR #12 | `adb396d38962f2577963694601ed45d447079783`, [43475741330](https://github.com/raleonys/mithrilhook/actions/runs/43475741330) | 153 native engine + two portable; this predecessor did not yet contain the seven installed-consumer jobs. |
| Prefix / byte-alias correction, PR #9 | `614be3d3f1971e508798be21badc5681d391a99a`, [43463874300](https://github.com/raleonys/mithrilhook/actions/runs/43463874300) | 153 native + two portable; prefix refusal and 3,024 byte-alias combinations. |
| Generated unwind, PR #4 | `e5ac0eff32408557830526de66a5dbe48e11bc7b`, [43454757280](https://github.com/raleonys/mithrilhook/actions/runs/43454757280) | 146 native + two portable; same tree as merged `d32fd189f1459e6f7b70002d1483ada78342f055`. |

The PR #4 x64/MSVC artifact records 139 genuine unwind checks and 290 registry/
retirement failure assertions with projected peer scheduling. These are not
290 independent real-thread schedules and are historical fixture counts.
Native churn, real-peer and registry tests are retained in later matrices.

The eleven-target production probe requires successful create/remove for all
named targets on the pinned Windows runner. It never enables or executes those
actual system functions. Owned-code execution and this create/remove probe do
not establish actual eleven-hook Citrine acceptance.

## Evidence boundaries

- Current correctness CI runs on Windows Server 2022. Comparative/source-form
  observations also cover Server 2025. These are identified hosted environments,
  not certification of every desktop Windows build or CPU.
- Projected Windows API tests and actual Linux x64 CPU diagnostics establish
  their recorded boundary; they are not genuine Windows suspension or unwind.
  Cross-compilation is build evidence, not Windows execution.
- Correctness-test durations do not rank performance. Use the separate
  [benchmark reports](BENCHMARKS.md) and their exact source/binary identities.
- Arbitrary ISA/handler translation, a universal thread-birth barrier,
  all-or-nothing multi-hook writes and universal unload safety are not claimed.
- Citrine startup, live detour/original calls, failure recovery, callback drain,
  shutdown and DLL unload remain application integration acceptance.

## Earlier provenance

The initial local snapshot in metadata/LOCAL_VALIDATION.json keeps its original
pending fields. The branding predecessor `742d6a7685a6c8c71f8210d8ea35f731e2864b28`
passed [43434695722](https://github.com/raleonys/mithrilhook/actions/runs/43434695722)
with 109 native + two portable tests. The conservative refusal-only unwind stage
`00c5f9a7cc4bfed1517a43e9dd9df9d8eaef2b93` passed
[43441584117](https://github.com/raleonys/mithrilhook/actions/runs/43441584117) but
accepted only 3/11 x64 targets; it was superseded by the generated-metadata work.

SAFE-FREEZE [43374271934](https://github.com/cyanoleon/minhook/actions/runs/43374271934)
and Citrine #363 [43391349173](https://github.com/raleonys/citrine-eclipse-mirage/actions/runs/43391349173)
validate their own sources. They are retained without rewriting their hashes or
being presented as execution of later MithrilHook code.
