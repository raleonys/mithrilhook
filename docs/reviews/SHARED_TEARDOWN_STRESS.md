# Shared Win32 teardown intermittently refuses after caller drain

## Review status

This review does not change the runtime engine. It records a repeated genuine
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
in each job passed before the stress step. PR #21 changes documentation and
the source manifest only, so it cannot alter the engine path under test.

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
