# Unaligned stack owners bypass generated-code retirement checks

## Review status

This is a report-only review. It does not change the runtime engine. The
finding was reproduced against `a05b879766b4c6a2f2c4f0b6e0d79667ce9a4f8f`,
the merge commit of PR #22 and current `master` at the time of review.

## Finding

Generated-code retirement examines each suspended peer's instruction pointer,
general-purpose registers and readable stack allocation. The stack loop reads
up to 512 bytes at a time into a `DWORD_PTR words[64]` array and tests only
`words[i]`. It therefore considers pointer-width windows at offsets
`0, sizeof(DWORD_PTR), 2 * sizeof(DWORD_PTR), ...` from the captured stack
pointer. It does not consider a complete pointer stored at any intervening byte
offset.

An x64 program may legally store and reload a pointer in a packed structure or
byte buffer without pointer alignment. If a suspended peer retains an original
trampoline pointer in such storage, the current scan can miss that owner,
return `MTH_OK` from removal or uninitialization and release the occupied
executable slot. A later reload would then use retired storage.

This is a false negative in the conservative retirement guard, not a decoder,
relocator or occupied-slot bitmap error. The bitmap correctly reports every
byte of the live slot when given the reconstructed address; the stack loop
never reconstructs the unaligned value.

## Deterministic projected-peer reproduction

The existing completion fixture was extended locally without changing the
engine. For each x64 byte offset 1 through 7, it created one disabled hook,
zeroed the projected peer stack, copied the returned `ppOriginal` value to
`(BYTE *)peer_stack + offset`, and called `MTH_Uninitialize` while that peer was
reported suspended. The fixture used the repository's exact `src/hook.c`,
`src/buffer.c`, `src/trampoline.c` and `src/hde/hde64.c` sources.

Every offset was missed:

```text
stack_offset=1 status=MTH_OK heap=(nil) blocks=(nil)
stack_offset=2 status=MTH_OK heap=(nil) blocks=(nil)
stack_offset=3 status=MTH_OK heap=(nil) blocks=(nil)
stack_offset=4 status=MTH_OK heap=(nil) blocks=(nil)
stack_offset=5 status=MTH_OK heap=(nil) blocks=(nil)
stack_offset=6 status=MTH_OK heap=(nil) blocks=(nil)
stack_offset=7 status=MTH_OK heap=(nil) blocks=(nil)
```

The null heap and block list prove that this was not only a status mismatch:
the generated-code owner was released. The same fixture's aligned stack case
continues to return `MTH_ERROR_MEMORY_PROTECT`, and its complete existing suite
passes 9,770 retirement, completion and page assertions. No unrelated crash,
timeout or injected API failure is accepted as evidence.

This evidence uses deterministic projected Windows peers on a host-x64 build;
it is not presented as a genuine Windows execution result. The loop and missed
offsets are architecture-independent C behavior, while a native acceptance
test remains required below.

## Contract boundary

Consumers still must stop admission, drain users and avoid calling or caching
an original pointer beyond successful retirement. The peer scan complements
that protocol and is not a universal unload-safety guarantee. This report does
not claim that a consumer may intentionally retain an original pointer and
ignore those obligations.

The finding is nevertheless observable within the guard's documented scope:
aligned values anywhere within an occupied slot defer retirement, and the
safety documentation says stack/register scans cover allocated code/metadata
slots without restricting storage alignment. Alignment of the container is
not a validity requirement for an x64 pointer copied with `memcpy` and later
reloaded the same way. The current success result is therefore a material blind
spot relative to the conservative check, even though a correctly drained host
must not depend on the check as its sole lifetime mechanism.

## Expected correction and acceptance

The retirement stack scan should inspect every complete pointer-width window
in each readable stack range, using alignment-safe loads. Chunk boundaries
must retain the final `sizeof(DWORD_PTR) - 1` bytes so a candidate spanning two
reads is not skipped. Read failures, short reads, inaccessible regions and the
existing 64 MiB budget must retain their fail-closed behavior. The occupied
slot bitmap remains the ownership predicate; allocator headers and free slots
must remain non-owners.

A genuine Windows x64 fixture should keep an externally suspended peer, save
its original stack bytes, write the actual published original pointer at
`RSP + offset` for every offset 1 through 7, and require both target-specific
removal and whole-engine uninitialization to return
`MTH_ERROR_MEMORY_PROTECT` while the slot remains committed. It must restore
the exact bytes/context before resuming the peer, drain it, then prove that
retirement succeeds and all owners are released. Aligned stack/register cases,
unused-slot/header controls, cross-block ownership and release-retry tests must
remain unchanged.

An exact negative control should restore pointer-width stepping and fail at the
first unaligned-owner refusal assertion. A test that merely stores an aligned
pointer, leaves it in a register, crashes after premature release or accepts a
retry-only teardown success does not demonstrate this correction.
