# MithrilHook development history

There is no published release or release tag. The CMake project version is
0.1.0; the entries below describe development milestones, not stable releases.

## Unreleased

- Reserve complete normal/hotpatch write intervals at creation, including
  disabled hooks; refuse intersecting owners before original publication.
- Cover both creation/removal orders, individual/all/queued activation,
  adjacent controls, disjoint alternate hotpatches and exact negative controls.

- Refuse a relocated x64 RIP-relative load or store of the five bytes the hook
  jump overwrites. LEA and accesses completely outside that window keep the
  absolute-address fixup; the adjusted trampoline is not used as a raw image.
- Require a proven complete RIP access range, including 512-byte FXSAVE/FXRSTOR
  operands. Refuse unknown/indexed/segment-dependent operands instead of
  assuming a 64-byte limit, and exercise native publication and execution.

- Resolve internal JMP/Jcc/LOOP destinations through the completed instruction
  map so backward branches remain correct after an earlier Jcc expansion.
- Refuse internal targets without a decoded instruction-boundary mapping;
  retain plain-loop controls and conservative forward-span growth refusals.
- Add complete native source/trampoline/detour/restore/retirement execution
  cases and a portable prefix/opcode/target-layout matrix for review #13.

- Refuse copied CALL-next/get-PC idioms and unsupported x64 REX2/APX forms
  before publication; explicitly document return-address-observation limits.
- Keep ordinary CALL and legacy/REX byte-alias controls; add nonexecuting APX
  refusal/publication cases and complete ordinary-CALL lifecycle coverage.

- Refuse ambiguous 66-prefixed near CALL/JMP/Jcc forms before publishing a
  trampoline; preserve ordinary unprefixed branch behavior.
- Normalize AH/CH/DH/BH and REX byte destinations in the unwind-neutral filter,
  preserving unrelated byte writes while rejecting protected frame changes.

- Add a native comparison of eight engines with pinned source/adapter/binary
  identities, 38 workloads, five OS/architecture/compiler environments, seven
  paired rounds, steady concurrent callers and separate cold/warm lifecycle data.
- Exercise the installed CMake package from a separate consumer in all seven
  native configurations, including static/shared and Debug/Release CRT linkage.
- Add 29 source-form compatibility cases per engine, real generated-unwind
  observations, broader eleven-API create/remove coverage, exact corrupted-call
  controls and offline recomputation of retained raw evidence.
- Preserve the historical donor benchmark's own source identity and distinguish
  m417z MinHook from MinHook-Detours. Library stable publication can precede
  Citrine integration after independent library release gates are met.

## Merged development milestones

### Evidence and open-work documentation — [PR #5](https://github.com/raleonys/mithrilhook/pull/5)

- Correct stale unmerged/native-pending wording and link exact source revisions
  to their completed Windows validation.
- Separate the refusal-only unwind audit from the later generated-metadata
  implementation so historical behavior is not presented as the current core.
- Record the missing comparative hook benchmark evidence and distinguish
  remaining acceptance work from documented engineering boundaries.

### Owned x64 trampoline unwind metadata — [PR #4](https://github.com/raleonys/mithrilhook/pull/4)

- Restore create/remove support for all eleven observed application targets on
  the pinned x64 Windows runner; Win32 also accepts all eleven. The production
  probe now fails on any refusal. These probes do not enable or execute the
  actual Windows API targets.
- Generate bounded version-2 runtime metadata for supported version-1 source
  prefixes on Windows 10 and later. Cover the complete jump-back so Windows
  does not misclassify FF25 as an already-restored tail epilogue. Older or
  unknown systems retain strict refusal when nonleaf metadata is needed.
- Keep the executable code budget at 64 bytes within fixed-address 256-byte
  x64 slots. Register metadata and flush generated code before publication.
- Retain exact owners after registration, deletion, publication cleanup or
  memory-release rollback failures. Retry registry operations outside owned
  suspension windows, under the consumer's closed-admission/drain protocol.
- Add genuine virtual-unwind and owned-code execution cases, native registry
  failure cases with projected peers, and older/unknown OS refusal controls.
- Refresh generated negative controls when their source or inventory changes.
- Complete 146 native test executions and two portable ASan/UBSan tests at the
  PR head and merged master. Exact revisions and runs are in
  [Validation](docs/VALIDATION.md).

### Thread coverage and partial-batch audit — [PR #3](https://github.com/raleonys/mithrilhook/pull/3)

- Reconcile suspended peer IPs against physically committed hook transitions
  after preparation or partial-batch failures; retain failed repairs for retry.
- Recheck live peer coverage after suspension and refuse an observed late birth
  before patching or retiring generated code. The final observation window
  remains a documented consumer-coordination boundary.
- Introduce conservative x64 unwind refusal and exact reconciliation, coverage
  and missing-metadata controls. This historical guard accepted only 3/11 x64
  targets and was superseded by PR #4's bounded generated-metadata support.
- Apply the approved five-pixel logo alignment without regenerating the artwork.

### Branding and license clarification — [PR #2](https://github.com/raleonys/mithrilhook/pull/2)

- Include the approved MithrilHook logo in the README and installed package,
  and document its visual identity.
- Distinguish the GPL-3.0-only distribution license from retained third-party
  BSD notices and provenance.

### Independent strict core — [PR #1](https://github.com/raleonys/mithrilhook/pull/1)

- Establish the independent MTH API, MithrilHook package/DLL identity and CMake
  target; remove the legacy compatibility header and inherited build products.
- Integrate strict SAFE-FREEZE, all five mutation cleanup barriers, correct
  disable IP relocation, completion journaling, cache publication checks and
  retryable generated-code/buffer/heap retirement.
- Integrate Citrine PR #363 bounded code reads, signed RIP displacement checks,
  EIP wrapping and VEX/relative-instruction classification fixes.
- Replace unaligned multi-byte decoder loads and displacement stores with
  memcpy-based access; add alignment regressions.
- Reject guarded/nonaccessible target and detour regions before hook allocation.
- Add same-thread reentry detection and diagnostics without a recursive lock.
- Retain injected-failure, real-peer, leaf-call, retirement and cleanup controls
  and add a reproducible source inventory.
- Validate feature branches through pull requests and reserve push validation
  for main branches, avoiding duplicate checks for the same PR commit.

Comparative performance and application/game acceptance remain open; see
[Benchmarks](docs/BENCHMARKS.md) and [Remaining work](docs/REMAINING_WORK.md).
