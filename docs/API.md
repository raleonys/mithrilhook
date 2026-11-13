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
before publication on Windows 10 and later. Older or unknown systems retain
strict refusal when nonleaf metadata is needed. Unknown/chained source formats, untranslated handler-bearing
bodies, interior nonleaf entries and undescribed stack/frame changes return
MTH_ERROR_UNSUPPORTED_FUNCTION. Registration failures return
MTH_ERROR_MEMORY_PROTECT without publishing an original. See UNWIND.md.

A copied CALL-next/get-PC idiom or unsupported x64 REX2/APX instruction returns
MTH_ERROR_UNSUPPORTED_FUNCTION before original-pointer publication. These forms
are refused, not emulated with stack operations that bypass control-flow
mitigations. Ordinary relative CALL remains supported within the documented
scope; general return-address introspection is not preserved by relocation.

Relative JMP/Jcc/LOOP destinations inside the five-byte patch interval are
resolved through the completed old-to-new instruction-boundary map. This
preserves backward targets after earlier instruction expansion. Destinations
inside another decoded instruction are unsupported. Existing conservative
refusal of instruction growth inside a pending forward span remains in force;
this does not introduce arbitrary overlapping-instruction or whole-body CFG
relocation support.

A relocated x64 RIP-relative memory operand that reads or writes the first five
bytes of the target returns MTH_ERROR_UNSUPPORTED_FUNCTION before publication.
Those bytes are replaced by the hook jump, so keeping the original absolute
address would observe the jump instead of the original value. LEA does not
access that memory and remains supported. Accesses completely outside the
five-byte window keep the existing absolute-address fixup when their complete
access range is known. Register-indexed bit strings, variable/unknown widths,
unmodeled vector/XOP operands and FS/GS-dependent linear addresses are refused
even if the nominal RIP address is outside the patch. FXSAVE/FXRSTOR use their
512-byte envelope. LEA ignores FS/GS and remains supported. The trampoline is
not a raw copy of the stolen bytes, so the operand is refused rather than
silently retargeted into it.

For RIP-relative PUSH, effective REX.W selects an eight-byte read even when 66
is also present; otherwise 66 selects two bytes and the x64 default is eight.
REX prefixes superseded by a later legacy prefix do not retain their W effect.

MTH_ALL_HOOKS selects the owned set for the documented enable/disable/queue
operations. Removal remains target-specific; uninitialize retires the complete
engine after the required quiescence. An already initialized engine must not be
silently adopted and later uninitialized by an unrelated consumer.

Creation reserves the complete physical patch interval even while disabled:
normal placement owns [target,target+5), and hotpatch-above placement owns
[target-5,target+2). An intersecting reservation returns
MTH_ERROR_UNSUPPORTED_FUNCTION without publishing ppOriginal. Exact duplicate
targets retain MTH_ERROR_ALREADY_CREATED. Adjacent intervals are permitted;
an interval remains reserved until its hook owner is completely retired.

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
