# Thread coverage, partial batches and x64 unwind audit

Audit base: accepted master `742d6a7685a6c8c71f8210d8ea35f731e2864b28`.
PR #3 introduced the thread/batch fixes and a refusal-only unwind guard. PR #4
added the owned-unwind follow-up and is merged as
`d32fd189f1459e6f7b70002d1483ada78342f055`. This document distinguishes those
stages; [Validation](VALIDATION.md) records their exact native results. The
scope is the engine before application integration.

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

### Historical PR #3 guard

The initial trampoline had no synthesized RUNTIME_FUNCTION entry. A relocated
push or stack allocation could therefore be mistaken for a leaf frame during
unwinding, losing return-address and nonvolatile-register restoration. Source
language-handler scopes also did not transfer merely by copying instructions.

PR #3 checked registered targets using RtlLookupFunctionEntry and bounded
ReadProcessMemory reads. It refused nonleaf interior entries, unsupported
versions/flags, handler/chained forms and any unwind operation within the copied
prefix. Operand payload slots were skipped according to the operation rather
than interpreted as primary offsets. Refusal published no hook/output pointer.

Its genuine runtime-function fixture proved source stack/return/RBX restoration;
the guard-removal control demonstrated the missing trampoline metadata and
complete hook/table/allocation/handle cleanup. This conservative guard narrowed
x64 create/remove support to 3/11 targets. That stage was not ready for the
application's eleven-hook integration.

### Current PR #4 support

The current core generates fixed-address version-2 metadata for a bounded set of
version-1 source prefixes on Windows 10 and later. It translates only completed
unwind operations through the actual relocation boundaries and covers the main
code through the jump-back. Native diagnostics showed that version-1 epilogue
scanning misclassified FF25 even with an extended prologue or chained fragment;
version 2 declares no epilogues and restores the expected caller state.

Source chains, interior nonleaf entries, untranslated handler-bearing bodies and
undescribed stack/frame changes remain refused. Handler-bearing prefixes wholly
inside the original prologue can be admitted. Unregistered custom code must
already obey the Windows leaf/unwind registration contract. Older/unknown
systems retain refusal when generated nonleaf metadata is needed.

Registration and generated-code cache completion precede publication. Metadata
and code storage remain owned through deletion, publication cleanup and
memory-release rollback failures. Registry operations run outside engine-owned
suspensions under the consumer's admission/drain protocol. See
[Unwind support](UNWIND.md) for the exact subset, slot layout and lifecycle.

The current native fixture checks exact caller stack/return state, RBX/RBP/XMM
restoration, frame offsets and allocation encodings. Owned source and trampoline
calls execute, including enable/detour/original/disable behavior. A separate
native-registry fixture injects ownership/recovery failures with projected peers
and verifies that registry calls never occur during owned suspension. The
missing-metadata negative control still requires its precise mismatch and
complete cleanup; unrelated crashes/timeouts are not accepted.

References:

- https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention
- https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64

## Validation and related asset change

The historical PR #4 workflow registered 23 tests on x64 and 18 on Win32, across seven
native configurations: 146 native executions plus two portable tests. The merged
PR #4 source passed [run 43456198204](https://github.com/raleonys/mithrilhook/actions/runs/43456198204).
These are correctness results, not comparative performance measurements. See
[Benchmarks](BENCHMARKS.md) and [Remaining work](REMAINING_WORK.md).

The target probe reports create/remove compatibility for the application's eleven
modern-Windows API names, without enabling a hook or executing its target or
trampoline. The historical PR #3 probe allowed individual unsupported
classifications to pass. The current production probe requires all eleven targets to be accepted
and fails on any refusal. All seven native cells accept 11/11 in the merged
PR #4 run. This is create/remove compatibility, not live eleven-hook acceptance.

Initial native audit head `00c5f9a7cc4bfed1517a43e9dd9df9d8eaef2b93` passed
138 native test executions and two portable tests in run
https://github.com/raleonys/mithrilhook/actions/runs/43441584117.
The MSVC Release artifact reports x64 create/remove support for `connect`,
`SHGetFolderPathA` and `SHGetFolderPathW`; the five registry functions,
`CreateProcessA/W` and `CryptQueryObject` were refused. Win32 accepted all eleven.
That refusal-only predecessor was **not ready for eleven-hook integration**.
The follow-up described in UNWIND.md supplies bounded generated metadata rather
than disabling that safety requirement. Its exact-head target gate must accept
all eleven pinned-runner targets; it no longer treats a refusal as a passing
production-probe result.

The x64 comparison fixture now also runs the same create-only probe against the
precisely guard-removed engine. It reports which refusals are introduced by the
unwind check rather than attributing every unsupported function to it by
assumption. Both probe processes must complete their owner cleanup successfully;
neither enables hooks or claims execution compatibility. Summaries are printed
in the workflow log as well as retained in the CTest artifact.

The same change includes the owner-approved original-logo alignment. It uses
the original raster artwork with an integer five-pixel translation, preserves
the wordmark and replaces no design through generative redrawing. It is included
with this substantive safety work rather than submitted as an asset-only PR.
