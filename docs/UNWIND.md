# Owned x64 trampoline unwind support

The refusal-only audit identified a compatibility blocker: eight of eleven
observed application targets were refused on x64. This implementation keeps
strict refusal for unsupported forms and generates metadata for a bounded,
tested subset instead of accepting unregistered stack-changing trampolines.

## Supported source subset

- An entry at the beginning of a registered version-1 runtime function.
- PUSH_NONVOL, ALLOC_SMALL/LARGE, SET_FPREG, SAVE_NONVOL/FAR and
  SAVE_XMM128/FAR operations whose code offsets map to relocated instruction
  boundaries. Payload slots are copied as data, not interpreted as code offsets.
- A prefix wholly inside the source prologue, including a handler-bearing
  function's prologue where the original handler is not yet applicable.
- For handlerless functions with a short prologue, a finite whitelist of copied
  body instructions that do not alter RSP or the active frame register.

Source chains, unrecognized versions/operations, interior entries, untranslated
language-handler scopes in the copied body, and undescribed body stack/frame
changes are refused. Unregistered source code must already be ABI-valid and
leaf-unwindable. This is not arbitrary x64 exception-scope translation.

## Metadata layout and jump-back semantics

X64 slots are 256 bytes. The executable code budget remains the original 64
bytes; the remaining fixed-address storage holds up to two runtime entries,
bounded unwind codes, a chained fragment and ownership state. Eleven hooks
still fit in one 4096-byte allocation. Win32 slot/code sizes are unchanged.

Only unwind operations completed within the copied source span are retained.
Code offsets are mapped through the actual old/new instruction boundaries;
the jump-back is not mistaken for a copied source instruction. Frame-register
metadata is retained only if frame setup was actually copied. No registration
is needed when the copied prefix remains leaf-unwindable.

The main prefix is described as a synthetic prologue. Copied body instructions
are admitted only when their stack/frame state remains described by those
operations. The absolute jump-back is a separate runtime range with a chained
record and a prologue covering its entire instruction/data span. This prevents
Windows from mistaking FF25 for a tail-call epilogue with an already-restored
stack. The relay, entered before the original prologue, remains leaf-unwindable.

## Publication, retirement and failure ownership

Metadata and runtime-entry storage do not move when the hook-entry array grows.
Registration and generated-code cache completion both precede publication of
the original pointer. Failed publication retains an unclosed registry/storage
owner for retry; it never returns a partially published pointer.

Runtime registry APIs may acquire process-global user-mode locks. They must not
be called while engine-owned peer suspensions could freeze a lock holder.
Retirement therefore scans for generated-code/metadata references, resumes and
releases its owned peers, then deletes tables and releases storage while the
consumer's original-call admission remains closed. The consumer must disable,
close admission and drain callbacks before retirement, and keep that state
through retries. The scan is not a universal admission or thread-birth barrier.

Deletion failure leaves the table and buffer registered and allocated. If a
memory release fails after deletion, registration is restored before recovery
is reported complete. Failed restoration remains discoverable and blocks new
mutations. Partial all-buffer retirement remains shutdown-only; deleted blocks
are never revisited. No table points into freed storage after successful cleanup.

## Native validation contracts

The runtime-function fixture uses genuine RtlAddFunctionTable,
RtlLookupFunctionEntry and RtlVirtualUnwind. It checks exact caller RIP/RSP,
saved RBX/RBP, frame setup before/after the prefix, nonzero frame offsets,
scaled/unscaled saved-register/XMM data and both large-allocation encodings.
Owned assembly targets and their trampolines are also executed; the initial
case exercises enable/detour/original/disable behavior. Artificial contexts do
not execute invented return addresses.

The failure fixture uses native registry APIs and projected peer scheduling to
assert that no registry call occurs during owned suspension. It injects initial
registration, deletion, code-flush, hook-entry allocation, memory release,
registration rollback and partial table/block teardown failures. Every surviving
registry, buffer, hook, peer array and heap owner remains discoverable for retry.

Removing unwind preparation must expose the exact unregistered-frame mismatch
and complete its cleanup; unrelated faults/timeouts are not accepted as proof.
The production target probe now fails unless all eleven pinned-runner targets
support create/remove. It never enables or executes the actual Windows targets;
full application acceptance and other OS builds remain separate validation.
