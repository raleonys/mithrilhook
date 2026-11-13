# MithrilHook development history

## 0.1.0 development candidate

- Register owned x64 unwind metadata for supported relocated prefixes, with a
  synthetic prologue covering the jump-back and an unchanged 64-byte code limit.
- Keep runtime-table registry calls outside owned suspension windows; retain
  and recover registration/deletion/storage failures without losing owners.
- Require all eleven pinned-runner targets to pass create/remove classification;
  add native virtual-unwind, owned-code execution and registry failure cases.
- Reconcile suspended peer IPs against physically committed hook transitions
  after preparation or partial-batch failures; retain failed repairs for retry.
- Recheck live peer coverage after suspension and refuse an observed late birth
  before patching or retiring generated code.
- Reject registered x64 targets whose relocated prefix needs unwind operations,
  language handlers or chained metadata that the trampoline does not provide.
- Add deterministic failure cases, genuine runtime-function/unwind checks and
  precise reconciliation/coverage/unwind negative controls.
- Report the eleven create-only target classifications and compare x64 results
  with the unwind guard removed; unsupported targets remain integration blockers.
- Apply the approved five-pixel logo alignment without regenerating the artwork.
- Established an independent MTH API, MithrilHook package/DLL identity and CMake
  target; removed the legacy compatibility header and inherited build products.
- Integrated strict SAFE-FREEZE, all five mutation cleanup barriers, correct
  disable IP relocation, completion journaling, cache publication checks and
  retryable generated-code/buffer/heap retirement.
- Integrated Citrine PR #363 bounded code reads, signed RIP displacement checks,
  EIP wrapping and VEX/relative-instruction classification fixes.
- Replaced unaligned multi-byte decoder loads and displacement stores with
  memcpy-based access; added alignment regressions.
- Rejected guarded/nonaccessible target and detour regions before hook allocation.
- Added same-thread reentry detection and diagnostics without a recursive lock.
- Retained native injected-failure, real-peer, leaf-call, retirement and cleanup
  controls and added a reproducible source inventory.
- Run feature-branch validation through pull requests and reserve push validation
  for main branches, avoiding duplicate checks on the same pull-request commit.
- Include the approved MithrilHook logo in the README and installed package,
  document its visual identity, and distinguish the GPL-3.0-only distribution
  license from retained third-party BSD notices.

This entry describes an unmerged development candidate, not a published stable
release or native acceptance of the final MithrilHook source.
