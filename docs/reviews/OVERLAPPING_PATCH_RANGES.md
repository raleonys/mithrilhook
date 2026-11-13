# Overlapping hook patch ranges are accepted and corrupt the first hook

Reviewed master: `af6675f63f6f94732e6000b9d528b3ddc0a4330c` (merged PR #14).
This PR records the finding without a runtime correction. Generated diagnostic
sources and binaries remained under the review checkout's ignored `build/`
directory.

## Minimal accepted layout

The diagnostic allocated executable code with two valid entry points at
`code` and `code + 2`. Both entries initially execute ordinary NOPs, join the
same `mov eax, 1; ret` body and return 1. Separate detours return 11 and 22.

The public API accepted every operation:

```text
MTH_CreateHook(code,     detour11, &original0)  -> MTH_OK
MTH_CreateHook(code + 2, detour22, &original2)  -> MTH_OK
MTH_EnableHook(code)                              -> MTH_OK
MTH_EnableHook(code + 2)                          -> MTH_OK
```

Each non-hotpatch entry owns five bytes. The physical intervals are therefore
`[code, code + 5)` and `[code + 2, code + 7)`. After the first enable, its
bytes began with a valid `E9 rel32`. The second enable wrote another `E9` at
offset 2, inside the first jump's four-byte displacement. A representative run
changed the prefix from `e9 0e 4f fe ff` to
`e9 0e e9 0c 4e fe ff`.

The second entry still reached detour22. Calling the first entry in a bounded
child process faulted with SIGSEGV on the actual x64 CPU because its jump
operand had been corrupted. Disable and uninitialize both returned `MTH_OK`,
restored the source bytes and left no projected runtime-function registrations.

This is not merely an uncoordinated external patch owner: both patch owners
were created by the same initialized MithrilHook instance through supported
public operations. `FindHookEntry` rejects only exact duplicate target
addresses. Creation does not compare the actual patch interval with existing
entries.

## Evidence boundary

The reproduction compiled the current `src/hook.c`, `src/buffer.c`,
`src/trampoline.c` and `src/hde/hde64.c`. It used the existing Linux projection
for Windows allocation, protection, registry and no-peer enumeration behavior,
then executed the generated jumps on a real Linux x64 CPU. This proves accepted
interval overlap, byte corruption and x64 execution failure. It is not a
native Windows peer-suspension or unwind-lifecycle run.

The current fault/recovery matrix independently completed 20,480 operation and
fault-mask combinations with 479,216 assertions. The overlap failure occurs
without injected OS failure, so retryable completion ownership does not prevent
it. PR #14's internal-branch remapping and PR #15's proposed RIP-relative
self-read refusal address different relocation cases.

## Required correction scope

After the new trampoline determines whether normal or hotpatch-above placement
is required, compute its complete physical write interval and reject creation
if it intersects any existing hook's interval. Normal patches own
`[target, target + 5)`; hotpatch-above entries own
`[target - 5, target + 2)`. Exact-target lookup alone is insufficient.

Regression coverage should include both creation orders, normal/normal,
normal/hotpatch and hotpatch/hotpatch intersections, adjacent non-overlapping
controls, individual enable, all-hooks enable, queued apply, removal in both
orders, restored source bytes and native Windows execution/cleanup. The chosen
public refusal status must be documented and must not publish `ppOriginal`.

Implementation and native Windows validation remain pending. This PR changes
only this report and its source-inventory entry.
