# MithrilHook validation

## Version and exact source identity

**Distribution version: 1.0.4.** The release includes all corrections through
PR #23. The exact tag/commit/tree, fresh native and benchmark workflow runs,
artifact hashes and independent audit results are recorded in the published
[1.0.4 validation asset](https://github.com/raleonys/mithrilhook/releases/download/v1.0.4/MithrilHook-1.0.4-VALIDATION.json).
The [release page](https://github.com/raleonys/mithrilhook/releases/tag/v1.0.4)
also retains installed packages, native logs and complete benchmark evidence.
Historical results below validate only their recorded sources; version and
documentation changes do not transfer their evidence to different bytes.

The validation matrix contains four x64 cells (MSVC Debug/Release static,
MSVC Release shared and clang-cl Release static) and three Win32 MSVC cells
(Debug/Release static and Release shared). It exercises public API calls,
real owned-code execution, peer/retirement behavior and exact negative controls.
Each cell also builds and executes an independent installed-package consumer.
The portable decoder and relocator run under Linux ASan/UBSan; the relocator
contains 143,571 assertions, including 511 PUSH prefix/range layouts and 1,040
CALL prefix/site/destination layouts plus ten forward-entry/expansion cases.
Internal CALL refusal is checked before output or entry-patch publication.
A generated native negative control removes only that refusal and must exit 1
at the exact refusal assertion before any unsafe original is executed.
Ordinary outside CALL controls execute source/original/detour/restore paths on
both architectures; registered x64 controls verify source v1/generated v2
unwind and actual generated-table retirement. The x87 policy adds 2,520
opcode/prefix/site layouts, 75 fixed/extended-state
controls and two copied-prefix/body-boundary controls. The native fixture
measures genuine source FIP, refusal before original publication, preserved
FIP through allowed original/detour/restoration paths and FP state cleanup.
Its generated negative control removes only the x87 guard and must fail at
the exact refusal assertion. Word-PUSH
range checks are structural; the registered native execution/unwind fixture
uses ABI-describable eight-byte stack allocations.

For 1.0.4 each installed consumer leaves prerelease consent disabled, accepts
exact 1.0.4 and compatible 1.0 requests, rejects major 2, and verifies full/numeric
metadata before linking and running.
Shared builds verify thirteen exact exports, product identity, numeric/full
version resources and a clear prerelease flag against VERSION.

Transition coverage adds 1,760 opcode/prefix/site layouts and nine positive
boundary/ordinary-instruction controls. Genuine Windows x64 tests read the
loaded no-argument NtYieldExecution stub, execute an owned source with a
source-resident RCX store, reject copied gates before publication, and verify
source/original/detour/restoration/retirement behavior when the syscall remains
outside the copied prefix. Privileged/trap/far-return cases are structural
only; native x86 does not execute a guessed service ABI. The exact guard-removal
control must exit 1 at its specific publication refusal. Previous CALL/x87
controls remain in the full matrix.

## Release acceptance matrix

The matrix registers 41 tests per x64 cell and 34 per Win32 cell: 266 engine
executions and seven installed consumers, 273 native total, plus two portable
tests. UD0/UD1/UD2 coverage adds 61,560 structural layouts (every ModR/M byte,
five copied offsets, eight legacy-prefix choices and sixteen single REX
prefixes), exact Windows source exception-address observations, source-resident
trap execution and a guard-removal control with a precise exit-1 assertion.

Retirement checks exercise unused/header values with actual and projected peers,
every byte of occupied slots in registers and stack, cross-block allocation,
failed release ownership, double-free refusal and the old whole-block predicate
as an exact negative control. Both Release shared cells run 250 independent
live-call processes: 5,000 sessions and 200,000 patch transitions per architecture,
with first-call teardown, zero bad results and zero residual handles required.
No retry-only success is accepted.

## Historical 1.0.3 trap and occupied-slot evidence

Combined source `f638fa03e7f5aaf72945243e97e94117de9620c7` passed
[43556129592](https://github.com/raleonys/mithrilhook/actions/runs/43556129592):
all seven native configurations, 259 native tests including consumers and two
portable tests. Each native cell reports 61,800 undefined-trap assertions and
both new exact negative controls. x64 shared completed 250 processes and
230,341,848 actual calls; Win32 shared completed 250 processes and 122,462,513
actual calls. Together: 10,000 sessions, 400,000 patch transitions, zero bad
results and zero residual handles. Artifact ZIP digests, source identities,
JUnit cases, installed packages and DLL resources were independently checked.
The earlier corrected-retirement-only source `2e474049bb4f6470724be6d9248a5d91b045795a`
also passed all seven native cells in
[43555956129](https://github.com/raleonys/mithrilhook/actions/runs/43555956129).
An independent repeat at the same combined commit passed all cells in
[43556595298](https://github.com/raleonys/mithrilhook/actions/runs/43556595298),
including another 500 processes, 10,000 sessions and 400,000 transitions. The
two combined-source runs total 1,000 independent processes, 20,000 sessions,
800,000 transitions and 809,933,121 actual calls, with zero bad results or
residual handles. These results belong to their recorded commits, not
subsequent documentation bytes.

## Historical PR #23 stack-owner acceptance

The new production-linked fixture keeps a real Windows peer externally
suspended, saves its exact stack/context, places the actual published original
at every alignment and across two read boundaries, and requires both removal and
whole-engine shutdown to refuse while storage stays committed. Edited stack
bytes are restored before the peer resumes; the worker drains with its padding
intact, then retirement succeeds and the handle baseline restores.

Projected cases additionally cover short first regions, odd region boundaries,
unaligned captured stack pointers, all live-slot boundary values, incomplete final
windows and read/query/protection/budget failures. The exact negative control
restores only pointer-width stepping and must exit 1 at its first unaligned-owner
refusal assertion. Existing aligned, unused/header, cross-block and release-retry
cases remain enabled. Corrected source `8464e2733095992edf60b99805b80ffbdedab5de` passed
[43560037514](https://github.com/raleonys/mithrilhook/actions/runs/43560037514):
all seven native cells, 273 Windows/package tests and two portable sanitizer
tests. The genuine unaligned-owner fixture reports 178 assertions per x64 cell
and 94 per Win32 cell. Projected completion reports 10,104 x64 and 9,272 Win32
assertions, including the new alignment/boundary/failure cases; the exact
stepping control passes on every cell. Artifact identities, JUnit results,
installed package bytes, thirteen DLL exports and stable 1.0.3 resources were
independently checked.

Both shared architectures passed 250 independent processes each: 10,000
sessions, 400,000 transitions, 356,183,335 actual calls, zero bad results and
zero residual handles. Each process required successful first teardown.
The same corrected source passed all five broad environments in
[43560037534](https://github.com/raleonys/mithrilhook/actions/runs/43560037534),
10,640 positive children and five independent retained-evidence audits.
Predecessor evidence is retained under its own source identity.

## Completed predecessor evidence

These records validate their pinned sources, not later candidate bytes.

| Stage | Exact source / run | Completed evidence |
| --- | --- | --- |
| Through PR #19 | `2860e5d71565eaf9ce64662ac238fe29f4d4a3bf`, [43514813440](https://github.com/raleonys/mithrilhook/actions/runs/43514813440) | 217 engine tests + seven installed consumers (224 native total), two portable tests; merged tree `39f496b1769e4796e890716a891fce669064a065`. Predates the transition correction and 1.0.2 metadata in #20. |
| Through PR #18 | `45ff055d4156ae6578e1bc9f3f207bcfd493f9cc`, [43509927578](https://github.com/raleonys/mithrilhook/actions/runs/43509927578) | 203 native engine tests + seven installed consumers (210 native total), two portable tests. Predates the x87 correction and 1.0.1 metadata in #19. |
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

The initial snapshot is archived unchanged as
[INITIAL_LOCAL_VALIDATION.json](../metadata/history/INITIAL_LOCAL_VALIDATION.json).
Its pending fields describe that initial development snapshot, not this release. The branding predecessor `742d6a7685a6c8c71f8210d8ea35f731e2864b28`
passed [43434695722](https://github.com/raleonys/mithrilhook/actions/runs/43434695722)
with 109 native + two portable tests. The conservative refusal-only unwind stage
`00c5f9a7cc4bfed1517a43e9dd9df9d8eaef2b93` passed
[43441584117](https://github.com/raleonys/mithrilhook/actions/runs/43441584117) but
accepted only 3/11 x64 targets; it was superseded by the generated-metadata work.

SAFE-FREEZE [43374271934](https://github.com/cyanoleon/minhook/actions/runs/43374271934)
and Citrine #363 [43391349173](https://github.com/raleonys/citrine-eclipse-mirage/actions/runs/43391349173)
validate their own sources. They are retained without rewriting their hashes or
being presented as execution of later MithrilHook code.
