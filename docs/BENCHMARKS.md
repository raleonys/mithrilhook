# Comparative hook-engine benchmarks

## Current evidence

The native comparison suite is implemented under `benchmarks/`. New measured
results are pending; no current MithrilHook performance ranking is claimed.

A historical SAFE-FREEZE report does exist at the pinned donor revision:
[BENCHMARK_RESULTS.md](https://github.com/cyanoleon/minhook/blob/311c8cc96c4a9c97e89ac3fc3a3c4a5a3f10bb38/BENCHMARK_RESULTS.md),
for code `a29eaa2aaa6e7eb8e4875c239d9ca861130d4b2a` and
[run 43374271934](https://github.com/cyanoleon/minhook/actions/runs/43374271934).
The earlier documentation audit missed this historical file. It compares the
old strict core, official MinHook and `m417z/minhook` modes; the latter is not
MinHook-Detours. It does not measure the current MithrilHook bytes, Microsoft
Detours, standalone SlimDetours or MinHook-Detours, nor call-through latency.
Its values remain historical evidence, with their original workload and safety
limits; they are not transferred to this fork's new runtime.

The 146 native CTest executions measure correctness contracts. CTest durations
are not calibrated operation timings. The eleven-target probe and its
guard-removed control measure support/refusal and owner cleanup, not latency,
throughput, CPU cost or memory consumption. Citrine's runtime-load benchmark
explicitly uses `install_hooks=false`; its XML/network/worker results cannot
rank hook engines.

## Comparison candidates

External sources and the exact patched relocation output are pinned in
`metadata/BENCHMARK_SOURCES.json`. These are separate native executables; the
current run remains pending and no new performance ranking is inferred.

| Candidate | Source identity | Performance status |
| --- | --- | --- |
| MithrilHook | [raleonys/mithrilhook](https://github.com/raleonys/mithrilhook), merged runtime `d32fd189f1459e6f7b70002d1483ada78342f055` | NOT MEASURED |
| Official MinHook | [TsudaKageyu/minhook](https://github.com/TsudaKageyu/minhook); inherited base in `metadata/PROVENANCE.json` | NOT MEASURED |
| Patched SAFE-FREEZE/Citrine predecessor | Exact donor and relocation inputs in `metadata/PROVENANCE.json`; choose and retain the complete built baseline | NOT MEASURED |
| m417z MinHook | [m417z/minhook](https://github.com/m417z/minhook), original freeze mode | NOT MEASURED |
| Microsoft Detours | [microsoft/Detours](https://github.com/microsoft/Detours) | NOT MEASURED |
| KNSoft SlimDetours | [KNSoft/KNSoft.SlimDetours](https://github.com/KNSoft/KNSoft.SlimDetours) | NOT MEASURED |
| MinHook-Detours | [m417z/minhook-detours](https://github.com/m417z/minhook-detours) | NOT MEASURED |

MinHook-Detours is a separate library/API from classic MinHook. Each engine needs
an explicit benchmark adapter. Pointer publication, transaction/queue semantics,
thread preparation and retirement guarantees must be recorded per adapter;
unsupported operations are N/A rather than fabricated equivalent work.
Benchmark adapters must not add legacy compatibility aliases to production.

## Required measurement and acceptance

- Build native Windows Release binaries with the same architecture, toolchain,
  optimization/CRT settings and owned target/detour fixtures. Retain source
  hashes, adapter sources, actual binary hashes and exact build commands.
- Verify target results, original-call behavior, enabled/disabled bytes and
  complete retirement before accepting a sample. Record refusals/errors and
  achieved thread coverage beside timings. A weaker success contract cannot
  silently stand in for strict preparation or safe retirement.
- Measure create, enable, disable, queued/batched apply where available,
  removal and engine teardown separately. Vary hook counts and peer-thread
  counts; use controlled child processes and report per-operation sample counts.
- Measure direct calls, detour calls and detour-to-original calls separately,
  with verified results and a method that prevents compiler elimination.
  Keep setup/teardown outside the call-through measurement interval.
- Retain raw samples, warmup policy, timer calibration, randomized paired order,
  repeated independent processes and uncertainty estimates. Report median and
  tail latency, throughput, CPU cost and actual allocated executable/metadata
  pages. X64 slots grew from 64 to 256 bytes; slot size alone is not a measured
  per-process memory or latency regression.
- Identify the OS build, CPU/VM, affinity/power policy and runner environment.
  Hosted CI can detect large regressions; small performance rankings require
  repeatable measurements on representative target hardware.
- Preserve correctness/ownership gates regardless of speed. Retain the raw
  artifact and an independently supplied artifact digest so another reviewer
  can repeat the analysis. Do not derive a benchmark from correctness-test
  wall-clock time or transfer results between different source revisions.

Native execution and review of this new suite remain open work. A completed comparison
must replace NOT MEASURED with identified evidence, including neutral or slower
results. Until then, engine selection is supported by the documented ownership,
compatibility and validation properties, not a performance superiority claim.
