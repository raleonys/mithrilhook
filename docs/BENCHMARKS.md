# Comparative hook-engine benchmarks

## Current evidence

No reproducible comparative hook-performance suite or timing result is retained
in this repository. The inspected predecessor checkout, donor repository tree,
and related Citrine benchmark documentation do not supply a performance result
for the current MithrilHook runtime source. Performance ranking is therefore
**NOT MEASURED**, and no speed or overhead advantage is claimed.

The 146 native CTest executions measure correctness contracts. CTest durations
are not calibrated operation timings. The eleven-target probe and its
guard-removed control measure support/refusal and owner cleanup, not latency,
throughput, CPU cost or memory consumption. Citrine's runtime-load benchmark
explicitly uses `install_hooks=false`; its XML/network/worker results cannot
rank hook engines.

## Comparison candidates

These are candidates for a future comparison, not measured or performance-ranked
engines. Record a reviewed immutable source revision for each before running.

| Candidate | Source identity | Performance status |
| --- | --- | --- |
| MithrilHook | [raleonys/mithrilhook](https://github.com/raleonys/mithrilhook), merged runtime `d32fd189f1459e6f7b70002d1483ada78342f055` | NOT MEASURED |
| Official MinHook | [TsudaKageyu/minhook](https://github.com/TsudaKageyu/minhook); inherited base in `metadata/PROVENANCE.json` | NOT MEASURED |
| Patched SAFE-FREEZE/Citrine predecessor | Exact donor and relocation inputs in `metadata/PROVENANCE.json`; choose and retain the complete built baseline | NOT MEASURED |
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

This suite and its native measurements remain open work. A completed comparison
must replace NOT MEASURED with identified evidence, including neutral or slower
results. Until then, engine selection is supported by the documented ownership,
compatibility and validation properties, not a performance superiority claim.
