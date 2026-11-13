# MithrilHook API

The public header is MithrilHook.h and the public prefix is MTH_. No legacy
header, binary export alias, old CMake target or old package name is provided.
Private allocator/relocator/decoder entry points use MthInternal_ symbols.

The API includes initialization/uninitialization, hook creation (including
named API lookup), enable/disable, queue enable/disable, queued apply, removal,
status formatting and per-thread operation inspection. The exact declarations
and export list are cross-checked by scripts/verify_sources.py.

Status values -1 through 12 retain the inherited meanings. The new value 13 is
MTH_ERROR_REENTRANT_CALL. These values support familiar diagnostics but are not
an ABI compatibility promise for another library. A source adapter must include
this header and call MTH_ names explicitly.

Creation publishes an original trampoline only after generated-code cache
completion succeeds. The pointer can be used while its hook remains owned;
creation of a hook does not enable it. The caller owns valid output storage
for the call, not a permanently retained void** variable. In contrast to
MinHook-Detours, this API does not keep updating that output variable during
activation/deactivation.

On x64, registered source functions are checked against their runtime-function
metadata. Supported prefixes receive fixed-address generated runtime entries
before publication. Unknown/chained source formats, untranslated handler-bearing
bodies, interior nonleaf entries and undescribed stack/frame changes return
MTH_ERROR_UNSUPPORTED_FUNCTION. Registration failures return
MTH_ERROR_MEMORY_PROTECT without publishing an original. See UNWIND.md.

MTH_ALL_HOOKS selects the owned set for the documented enable/disable/queue
operations. Removal remains target-specific; uninitialize retires the complete
engine after the required quiescence. An already initialized engine must not be
silently adopted and later uninitialized by an unrelated consumer.

Failures can follow physical progress. After cache/protection failure, enabled
state records written bytes and completion ownership remains reachable. New
mutations must recover pending completion first. Partial block retirement
allows only further teardown. MTH_ERROR_MEMORY_PROTECT can therefore indicate
incomplete native preparation, completion, retirement or cleanup; it is not
permission to discard the owner. See SAFETY.md for the consumer protocol.

After failed preparation or a partial batch, peer IPs are reconciled to physical
hook state before resumption. A failed context repair remains an owned retryable
operation. Queued changes for unwritten targets remain pending; a caller can
retry apply or explicitly change that intent after pending cleanup completes.

Unwind-table deletion failure retains both the table and executable storage.
If memory release fails after deletion, registration is restored; a failed
restoration remains an owned recovery obligation and blocks new mutations.
Keep original-call admission closed during failed retirement and recovery.

MTH_IsOperationInProgressOnThisThread is an observation, not a cross-thread
reservation or a safe-unload verdict. Error formatting and this observation do
not acquire the engine lock. A same-thread recursive mutation is rejected
before acquiring that lock and does not change hook outputs.
