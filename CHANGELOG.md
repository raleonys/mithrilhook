# MithrilHook development history

## 0.1.0 development candidate

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

This entry describes an unmerged development candidate, not a published stable
release or native acceptance of the final MithrilHook source.
