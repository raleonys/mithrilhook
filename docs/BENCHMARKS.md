# Native hook-engine comparison

## Evidence and historical results

The suite under `benchmarks/` produces native Windows results for an identified
source/build, with raw samples and an offline auditor. Reports are retained in
[Native hook-engine benchmarks](https://github.com/raleonys/mithrilhook/actions/workflows/benchmarks.yml)
artifacts and linked from the implementation PR. Cite a completed run and its
exact head/artifact digest; this protocol alone is not a performance result or
a universal engine ranking. Correctness-test durations are not benchmarks.

A historical SAFE-FREEZE report is retained at
[BENCHMARK_RESULTS.md](https://github.com/cyanoleon/minhook/blob/311c8cc96c4a9c97e89ac3fc3a3c4a5a3f10bb38/BENCHMARK_RESULTS.md),
for code `a29eaa2aaa6e7eb8e4875c239d9ca861130d4b2a` and
[run 43374271934](https://github.com/cyanoleon/minhook/actions/runs/43374271934).
The earlier documentation audit missed this historical file. It compares the
old strict core, official MinHook and `m417z/minhook` modes. It does not measure
current MithrilHook bytes, Microsoft Detours, standalone SlimDetours or
MinHook-Detours, nor call-through latency. Its original safety/workload limits
remain; values are not transferred to the new fork. Citrine's runtime-load
benchmark uses `install_hooks=false` and cannot rank hook engines either.

## 1.0.5 release evidence

The 1.0.5 comparison must be generated and audited against the final selected
source. PR #25 changes page-offset arithmetic and diagnostic types; earlier
measurements are not relabeled as results for these bytes. Current runs are
available through the workflow above; a completed exact-head run and its
artifacts are required for the release review.

## Published 1.0.4 release evidence

The release includes the unaligned-stack retirement correction and all reviewed
changes through PR #23. Its fresh exact-source measurements and independently
audited datasets are attached to the
[official v1.0.4 release](https://github.com/raleonys/mithrilhook/releases/tag/v1.0.4).
The [validation asset](https://github.com/raleonys/mithrilhook/releases/download/v1.0.4/MithrilHook-1.0.4-VALIDATION.json)
pins the measured commit, workflow runs and artifact digests. The readable
[benchmark report](https://github.com/raleonys/mithrilhook/releases/download/v1.0.4/MithrilHook-1.0.4-BENCHMARKS.md),
full timing CSV, comparison PNG/PDF and five raw environment ZIPs are retained
with that release. Prior reports keep their actual source and version.

## Historical development measurements

The following results predate public version 1.0.4 and are retained as
historical evidence, including the unpublished 1.0.3 correction candidate.
Corrected source `8464e2733095992edf60b99805b80ffbdedab5de` passed all five jobs in
[43560037534](https://github.com/raleonys/mithrilhook/actions/runs/43560037534):
eight engines, 38 workloads, seven paired rounds and 10,640 isolated positive
children. Artifact digests, exact source/version identities and five independent
Linux offline audits of streams, checksums, recipes and recomputed statistics
passed. Every actual-API create/remove probe accepted all eleven targets;
those system functions were never enabled or executed.

Timings, paired intervals, CSV/plots and raw evidence identify this measured
source. Expanded stack scanning affects retirement; results are controlled-fixture
measurements, not application acceptance or an equivalent-safety ranking.
A later documentation-only commit does not relabel these measured bytes.

The pre-#23 source `f638fa03e7f5aaf72945243e97e94117de9620c7` passed
[43556129567](https://github.com/raleonys/mithrilhook/actions/runs/43556129567),
all five environments, 10,640 positive children and five independent audits.
It contains the earlier trap/occupied-slot corrections but predates byte-window
stack scanning; its values remain predecessor evidence.

The previous unpublished 1.0.2 source `48fbc8e53f84c19347fb9419239165c59955cc43`
passed all five environments in
[43523185080](https://github.com/raleonys/mithrilhook/actions/runs/43523185080),
10,640 positive children and five independent offline audits. It predates #21/#22.

- Broad #12-era source `f1f32266b5d0392a830269ef9c5894099126d60e`,
  [43477964529](https://github.com/raleonys/mithrilhook/actions/runs/43477964529):
  all five environments passed, 10,640 positive children. This predates
  #14/#15/#16/#17 and is not a performance measurement of the release candidate.
- Focused pre-#9 / #9 / #12 comparison, source
  `fa80d956ebc4cad0a8d3eb4bd27757f35ffb8355`,
  [43476882976](https://github.com/raleonys/mithrilhook/actions/runs/43476882976):
  three environments, five workloads, twenty paired rounds, 900 positive
  children. The isolated runner is retained on perf/review9-ab; that experiment
  branch changes its CI workflow and is not a production merge target.
- The 1.0.0-rc.1 candidate's exact-head broad run is tracked in
  [PR #17](https://github.com/raleonys/mithrilhook/pull/17). Cite its completed
  run and artifacts for the PUSH correction and candidate version.
  Exact source `f006e53116b61ed9baabec025ed6bb26a7c6c7eb`,
  [43494694136](https://github.com/raleonys/mithrilhook/actions/runs/43494694136):
  all five environments and five independent offline re-audits passed,
  10,640 positive children. This predates #18's internal-CALL refusal; it is
  not a timing measurement of the later source.

- The unpublished 1.0.1 source `2860e5d71565eaf9ce64662ac238fe29f4d4a3bf`,
  [43514812907](https://github.com/raleonys/mithrilhook/actions/runs/43514812907):
  five environments and five independent offline audits passed, 10,640 positive
  children. It includes #19, predates #20 and is not relabeled as 1.0.2.

## Immutable candidates and build context

`metadata/BENCHMARK_SOURCES.json` pins seven external repositories and the exact
Citrine relocation patch/output hash. The MithrilHook candidate is the exact committed benchmark head. Its
corrections and version are determined by that source manifest, not by a moving
branch name.
Every executable has a source/input/binary receipt; adapters are separate from
production and keep each engine's actual API semantics.

| Candidate | Selected input | Adapter contract |
| --- | --- | --- |
| MithrilHook | Exact committed benchmark source head | Strict automatic observation, physical-state repair and retryable retirement ownership |
| Official MinHook | `TsudaKageyu/minhook` at `8af6b4acae5a9388fd742b56fa79ece89d96f823` | Original/default freeze; separate create/enable/remove |
| Official MinHook pinned v1.3.4 | `TsudaKageyu/minhook` v1.3.4 at `c3fcafdc10146beb5919319d0683e44e3c30d537` | Pinned stable original/default freeze; separate create/enable/remove |
| Patched predecessor | `cyanoleon/minhook` at `311c8cc96c4a9c97e89ac3fc3a3c4a5a3f10bb38`, strict ON, plus exact Citrine #363 relocator output | SAFE-FREEZE completion/retirement ownership; original MH API |
| m417z MinHook | `m417z/minhook` at `4f18d1809a81e6c700bcc4a21aeb43ade72bbf8b` | Original freeze mode; no unsafe-none or fast-undocumented mode |
| Microsoft Detours | `microsoft/Detours` at `1dbd4ea281d73d478aa8d09a8b83fbd265f715f7` | Attach/detach transactions; explicit UpdateThread for current and every owned idle peer |
| KNSoft SlimDetours | `KNSoft/KNSoft.SlimDetours` at `0255fac24b12781e0f0c35e0ae71bd7fc45411ee` | Official transaction implementation with default automatic suspension |
| MinHook-Detours | `m417z/minhook-detours` at `e7d5427ede9e658f1810e742822fab2936e058da` | Distinct API/implementation, default suspension and persistent-address original slots |

MinHook-Detours is distinct from both classic MinHook candidates. No production
legacy aliases are introduced. Detours/SlimDetours have no separate create or
engine-initialize API: their absent stages are N/A. Complete install/removal
covers each adapter's entire workflow, while individual stages can perform
different work. Successful timings do not establish equivalent safety.

The standalone build uses Release `/O2 /Ob2`, `/MT`, LTO off, C++17 and the same
C language mode within each compiler job. Pinned dependencies are kept under
`build/`, with notices included alongside artifact binaries. Official SlimDetours
uses its supported caller-supplied NDK path with pinned PHNT headers bundled by
MinHook-Detours. The benchmark compile context supplies missing CRT/SDK includes,
modern NTDDI declarations and, for MSVC x64 C, the explicit pointer type for the
pinned sources' `typeof(&RtlIsEcCode)` expression. No engine algorithm is edited.
These are benchmark build dependencies, not new MithrilHook dependencies.

## Performance matrix

Five independent environment jobs run on Windows Server 2022 x64/Win32 MSVC,
Windows Server 2022 x64 clang-cl, and Windows Server 2025 x64/Win32 MSVC. Record
the actual OS build, compiler, CPU/VM, logical processors, affinity and power
policy from each artifact. Do not pool their timings into one architecture,
compiler or hardware ranking; these server jobs are not desktop-game tests.

Each job runs seven paired rounds with seeded randomized case/candidate order:

- Thirty lifecycle cases: 1/4/11/32/64 hooks crossed with 0/1/4/16/32/64 owned
  idle peers.
- Eight steady-concurrency cases: 1/11 hooks and 1/4/16/64 active callers, with
  hooks kept enabled and all callers joined before mutation or retirement.
- 2,128 isolated positive child processes per job, 10,640 across five jobs.
- Three complete engine lifecycles per child. Cold denotes the first engine
  lifecycle in an already warmed process, not a cold OS/CPU; warm denotes the
  following two. Report create, activate, single disable/enable, queued apply or
  transaction toggles, disable, retire and complete install/removal separately.
- Direct, detour-only, detour-to-original and original-trampoline calls: seven
  batches of 500,000 verified calls each. Concurrent cases add three synchronized
  500,000-call batches per worker. Main-thread timing affinity is pinned; worker
  scheduling remains the recorded process/OS policy.

Source targets are owned, ABI-valid leaf fixtures with distinct per-hook values.
Timers exclude reporting, fixture setup and result checks. Each phase verifies
source/detour/original results, exact restored source bytes and handle cleanup.
There is no live provider, network target, game callback or application DLL here.
Original slots remain stable, and no caller races a pointer update or free.

Raw QPC ticks, frequency and calibration are retained. Summary medians and
p95/p99 describe the retained batch samples; call-batch averages are not
individual-call population tail latency. Paired intervals bootstrap the seven
per-process round medians against MithrilHook within a case/job. Small changes
and seven hosted-VM rounds do not establish cross-host speed superiority.
Executable private pages, process private commit and quantized process CPU
observations are separate; private commit is not a pure engine allocator count.
Zero CPU ticks and retained executable-page deltas are reported, not hidden.

## Compatibility and safety observations

Each job also runs 29 source-form cases per engine: ordinary leaf, RIP/absolute
load, relative CALL/JMP, conditional and LOOP branches, short/hotpatch source,
registered nonleaf, interior entry, a valid RBP frame with CH modification,
handler-bearing body, and 66-prefixed CALL/JMP/all sixteen near Jcc conditions.

The current MithrilHook candidate must meet explicit acceptance/refusal oracles.
Positive x64 frame cases use actual RtlVirtualUnwind to verify exact caller
stack/return and saved-register state. Unsupported/interior/handler-body and
ambiguous-prefix cases must refuse cleanly. Architecture-specific N/A results
are distinct. Other engines' API refusals, failed cases and missing generated
unwind metadata remain visible. A baseline failure is never relabeled a passing
negative control or included as a timing sample. Creation-only acceptance does
not prove correct execution or translated handler scopes.

A separate MithrilHook probe records create/remove support for the actual eleven
application API names on every environment, without enabling or executing them.
The production correctness workflow retains its strict 11/11 Windows-2022 gate;
refusals in this broader OS probe are explicit deployment gaps, not application
acceptance. Enabling arbitrary system API hooks is outside this timing harness.

## Run and audit

From a clean, committed native Windows checkout:

```powershell
python scripts/verify_sources.py
python benchmarks/prepare.py
cmake -S benchmarks -B build/bench-native -A x64 -T v143
cmake --build build/bench-native --config Release --parallel 2
python benchmarks/run.py --build build/bench-native --output build/bench-results
python benchmarks/run.py --audit build/bench-results
```

Use Win32 or ClangCL for the corresponding jobs and a fresh result directory.
Benchmark inputs, VERSION, production sources/headers and package/build changes
trigger the performance workflow on PRs; it also supports manual dispatch.
This keeps core corrections from silently retaining older timing evidence.
The production library/build defaults are unchanged. The correctness workflow
also builds a separate consumer from the installed package in all seven native
cells, checking both static and shared package use before application integration.

The artifact includes binaries/receipts/notices, source and dependency manifests,
raw JSON/stdout/stderr, compatibility rows, target classifications, complete
recipe, summaries and REPORT.md. Retain its independently supplied ZIP digest.
The offline auditor runs without executing Windows binaries and recomputes all
summary/interval fields (normalized to eight decimal places for portable libm
rounding), validates the randomized schedule and complete case/round/sample coverage and
checks raw/binary/source identities and call checksums. Duplicate JSON keys,
nonfinite values and optimized Python assertion bypass are refused.

Every engine must fail a deliberately corrupted timed detour-to-original
checksum at its exact oracle; crashes/timeouts cannot satisfy that control.
An unrelated correctness failure blocks the positive timing run. Offline sample
mutations separately exercise checksum, operation-count and duplicate-index
refusals. Hash consistency is not execution attestation: independently review
the successful native workflow head, build/measurement/audit steps and artifact
digest before citing results. [Remaining work](REMAINING_WORK.md) separates
library release gates from Citrine's later integration acceptance.
