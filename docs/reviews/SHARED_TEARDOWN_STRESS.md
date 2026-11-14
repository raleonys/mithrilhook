# Shared Win32 teardown intermittently refuses after caller drain

**Status: resolved and included in 1.0.4 (PR #21, originating in review #22).** Retirement tracks occupied slots while excluding free slots and allocator headers.

This is a historical review record. The finding, reproductions, counts and
version decisions below refer to their stated development baselines. They are
not open defects or current publication instructions. Current contracts and
release evidence are in [API](../API.md), [Safety](../SAFETY.md),
[Validation](../VALIDATION.md) and [Release](../RELEASE.md).

## Review status

This review corrects the retirement ownership predicate after a repeated genuine
Windows failure against `c60123e4c15c9be982e3b9238cef220a298d140b`, the merge
commit of PR #20, and extends the existing diagnostic to the x64 shared build.
The x64 result is required before assigning the Win32 observation to the
project's x64 deployment target.

## Finding

PR #20 added a bounded stress step that launches the Win32 Release shared
`mithrilhook_live_call_contracts.exe` in 100 independent processes. Each
process owns its generated target, joins its active caller, closes the exact
thread/event handles, removes the first hook, recreates and enables it, then
calls `MTH_Uninitialize` with no admitted caller.

The first PR #21 validation attempt completed 28 independent processes and
failed in process 29. A same-commit rerun completed 42 and failed in process
43. Both failures occurred in session zero with the same signature:

```text
status=MTH_ERROR_MEMORY_PROTECT
target_called=0
bytes_restored=1
expected=8b44240483c007c20400909090909090
actual  =8b44240483c007c20400909090909090
```

Across the two attempts, 70 independent processes completed 1,400 sessions
and 56,000 patch transitions before the two failures. The ordinary CTest run
in each job passed before the stress step. The initial PR #21 revision in those attempts changed documentation and the
source manifest only, so it could not alter the engine path under test.

The expanded PR #22 run reproduced the Win32 failure a third time in process
44, again in session zero with exact source restoration. Its immediate Win32
error was `ERROR_ACCESS_DENIED` (5). The three runs therefore completed 113
independent Win32 processes, 2,260 sessions and 90,400 patch transitions before
three same-signature teardown refusals.

The engine safely refused rather than leaving patched bytes: the exact target
image was restored. The defect is nondeterministic retirement completion after
the fixture has explicitly joined its only caller, not demonstrated unsafe
execution or byte corruption.

## Evidence boundary

The repeated failure is currently established only for Win32 Release with the
shared DLL. MithrilHook's intended Citrine deployment is x64 Windows. The prior
workflow ran the 100-process diagnostic only on Win32, so a clean single x64
CTest process cannot exclude the same timing or ownership path at useful
pressure.

This review therefore runs the unchanged stress recipe on both Release shared
architectures. A passing x64 run is target-specific evidence for that run, not
a correction of the Win32 defect or proof that the failure is impossible at a
higher process count.

The PR #22 x64 shared job completed all 100 independent processes: 2,000
sessions, 80,000 patch transitions and 78,121,150 actual target/original calls.
It reported zero bad results and zero residual handles. The observed teardown
failure is consequently not established on the intended x64 deployment
architecture; it remains a reproduced Win32 shared defect and an x64 stress
coverage requirement.

## Required diagnosis and acceptance

The current public status cannot distinguish peer coverage/refusal, retained
IP ownership, cache/protection completion, buffer release or heap destruction.
Before changing policy, a bounded test-only trace should record the exact
failure stage, peer thread ID/count, register or stack match address when
retirement detects a trampoline reference, retained buffer interval and the
immediate Win32 error from a failed API.

The correction must not disable conservative peer scanning merely to make the
stress green. It must show whether the refusal is a real live reference, a
stale-value false positive, a transient enumeration/coverage race or an API
completion failure, then preserve retry ownership for every rejected case.

Acceptance requires repeated independent-process runs on both shared
architectures with every caller joined, exact source restoration, successful
first teardown, zero bad call results and zero residual handles. A retry-only
success, unrelated process failure or reduced stress count is not sufficient.

## Root cause and correction

Two bounded diagnostic builds retained the original refusal policy and recorded
only fixed fields during peer suspension; output occurred after that scan.
[Run 43555405469](https://github.com/raleonys/mithrilhook/actions/runs/43555405469),
commit `9b2aca2f1cfe28bb4d824e6f2fd7b6983719fc56`, recorded a stack-word match
`0x01010100` during `ACTION_RETIRE`, not an OS release or protection failure.
[Run 43555674087](https://github.com/raleonys/mithrilhook/actions/runs/43555674087),
commit `52b6a5c`, additionally recorded the sole occupied trampoline at
`0x01010FE0`. The rejected value belongs to unused slot 8 in the same
`0x01010000` block; the published entry occupies slot 127. Immediate Win32 error
was zero. Earlier `ERROR_ACCESS_DENIED` alone did not identify the cause.

`MthInternal_IsBufferAddress` previously treated every byte of a 4096-byte block
as a published trampoline, including allocator bookkeeping and free slots. A
small per-block allocation bitmap now identifies occupied slots independently
of code bytes and free-list contents. Every byte of a live code/metadata slot
still blocks retirement when observed in any scanned register or stack word.
Free slots and the allocator header do not. Failed final release preserves the
bit and allocation; a later successful release clears ownership. Double free
is refused without corrupting the map. No scan, peer-coverage check, read-failure
refusal or cleanup ownership barrier is disabled. No success retry was added.

The temporary trace and diagnosis-only job are removed from the corrected tree.
Deterministic projected-peer checks cover the unused/header reproducer, every
byte of a live slot in registers and stack, allocation across block boundaries,
release failure/retry, double-free refusal and full ownership retirement. An
exact control restores only the old whole-block predicate and must exit 1 at
`unused slot and header values do not block whole-engine retirement`. A genuine
Windows peer separately proves first-call cleanup with an unused-slot register
value and allocator-header stack word, while the existing live-pointer checks
continue to refuse retirement. Both shared architectures retain the unchanged
250-independent-process live-call stress gate (increased from 100).

Combined source `f638fa03e7f5aaf72945243e97e94117de9620c7` passed
[43556129592](https://github.com/raleonys/mithrilhook/actions/runs/43556129592):
all seven native cells and both 250-process stress gates, 10,000 sessions,
400,000 patch transitions, 352,804,361 actual calls, zero bad results and zero
residual handles. All 500 independent processes completed their first teardown
successfully. Both new exact controls passed. This demonstrates the diagnosed
unused-slot correction under the measured conditions; stale values matching
an occupied slot can still conservatively defer cleanup. The host's admission,
drain and module-lifetime obligations remain unchanged.

An independent repeat at the same commit,
[43556595298](https://github.com/raleonys/mithrilhook/actions/runs/43556595298),
passed all seven native cells and both stress gates again. The two combined-source
runs total 1,000 independent processes, 20,000 sessions, 800,000 transitions and
809,933,121 actual calls, with zero bad results or residual handles.
