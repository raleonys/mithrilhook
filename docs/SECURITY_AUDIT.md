# Thread coverage, partial batches and x64 unwind audit

Base: accepted master `742d6a7685a6c8c71f8210d8ea35f731e2864b28`.
The scope is the engine before application integration. Native execution,
source inspection, cross-builds and application acceptance remain distinct.

## Preparation and partial-batch context mismatch

Preparation relocated every peer for the planned transitions before any target
write. A later protection failure could leave an unchanged enabled target while
a peer had already been redirected from its trampoline back into that still
patched target. Failed preparation could also leave earlier context changes.

Each owned peer now records its original IP, and each hook records its physical
state before the transaction. Before any peer resumes, reconciliation computes
its destination from the original IP and only physically committed transitions.
Unwritten targets retain their old mapping; written targets retain their new
mapping. Failed GetThreadContext/SetThreadContext repairs keep the exact peer
array suspended and discoverable for retry, after patch completion and before
resume/close/free. No second peer set is acquired while repair is pending.

Tests cover single-disable pre-write failure, second-target batch failures with
peers in written and unwritten targets, retrying queued changes, later-peer
preparation failure and persistent read/write context-repair failures. The
reconciliation-removal control must fail at its precise physical-mapping oracle.
The stale-disable control now mutates the final reconciliation mapping, so the
new recovery layer cannot accidentally mask the control's intended defect.

Batch target writes remain sequential. This change does not promise automatic
whole-batch byte rollback or hide a physically committed prefix.

## Thread born during enumeration/preparation

The original observation preceded peer suspension. A thread created in that
window could be absent from the owned set. A second stable-handle observation
now verifies coverage after suspension; an observed live peer without an owned
suspended identity rejects the operation before target writes or buffer release.
Cursor failures preserve emergency ownership as in the original enumeration.

Tests introduce a distinct live peer only on the second observation and require
unchanged bytes, restored original IP, retained hook ownership and complete
cleanup. A separate case refuses retirement. Disabling verification must reach
the exact late-peer negative-control oracle. The genuine thread-churn fixture
continues to distinguish completed operations from explicit safe refusals.

There is still a final observation-to-write/release interval. External thread
creation, APCs and other uncoordinated host activity are not globally blocked.
The caller must coordinate thread creation/admission for stronger guarantees.
No loader-lock acquisition, fixed PEB offset or universal barrier is claimed.

## x64 runtime-function and unwind metadata

The trampoline has no synthesized RUNTIME_FUNCTION entry. A relocated push or
stack allocation can therefore be mistaken for a leaf frame during unwinding,
losing the return-address and nonvolatile-register restoration described by the
source function's metadata. Source language-handler scopes also do not transfer
merely by copying instructions.

Creation checks registered targets using RtlLookupFunctionEntry and bounded
ReadProcessMemory reads. It refuses nonleaf interior entries, version/flag forms
outside the supported subset, handler/chained metadata and any unwind operation
within the bytes actually relocated. Extra unwind-code operand slots are skipped
according to the operation; they are not mistaken for primary code offsets.
The jump-back instruction is excluded from the original relocated-byte count.
No output pointer or hook entry is published for a refused function.

The native fixture registers a real source RUNTIME_FUNCTION, calls
RtlVirtualUnwind on a bounded artificial context and proves correct source
return-address, RSP and RBX restoration. Removing the guard must expose a real
trampoline without equivalent metadata and report its exact mismatch, followed
by complete hook/table/allocation/handle cleanup. A neutral-prefix function is
accepted and checked against the source leaf-unwind behavior. Language-handler
and interior-entry cases are refused.

This deliberately narrows supported x64 targets. A target that previously
created successfully may now return MTH_ERROR_UNSUPPORTED_FUNCTION. Application
integration must check all actual hook targets; this audit does not establish
their compatibility. Unregistered custom code must already obey the Windows
leaf/unwind registration contract. General generated unwind tables, language
scope translation and arbitrary unwind support are not implemented.

References:

- https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention
- https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64

## Validation and related asset change

The workflow registers 21 tests on x64 and 18 on Win32, across seven native
configurations, plus the two portable decoder/relocator tests. Results must be
read for the exact PR head; configured or cross-built tests are not native PASS.

The target probe reports create/remove compatibility for the application's eleven
modern-Windows API names, without enabling a hook or executing its target or
trampoline. Its supported/refused status checks and unchanged-byte checks can
pass while individual targets remain unsupported. The per-target results must
be reviewed before integration; the probe is not eleven-hook acceptance.

The same change includes the owner-approved original-logo alignment. It uses
the original raster artwork with an integer five-pixel translation, preserves
the wordmark and replaces no design through generative redrawing. It is included
with this substantive safety work rather than submitted as an asset-only PR.
