# Unaligned stack owners bypass generated-code retirement checks

**Status: resolved and included in 1.0.4 (PR #23).** Every complete pointer window is scanned across read/region boundaries.

This is a historical review record. The finding, reproductions, counts and
version decisions below refer to their stated development baselines. They are
not open defects or current publication instructions. Current contracts and
release evidence are in [API](../API.md), [Safety](../SAFETY.md),
[Validation](../VALIDATION.md) and [Release](../RELEASE.md).

## Review status

This review corrects the retirement scan with alignment-safe byte windows. The
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

## Correction and regression coverage

The scan now advances one byte for each complete pointer-width candidate, using
`memcpy` into a properly aligned scalar. A fixed local buffer retains the final
`sizeof(DWORD_PTR)-1` bytes across reads and adjacent readable regions in the same
stack allocation. Only newly read bytes consume the existing 64 MiB budget.
Partial final windows are not padded with bytes outside the allocation. Failed
or short reads, query failure, guard/no-access/uncommitted regions and budget
exhaustion still reject retirement. The occupied-slot predicate is unchanged.

The deterministic completion fixture now exercises all alignments, both read
boundaries, pointers into both ends of live slots, short first regions, odd
region boundaries, unaligned captured SP and incomplete trailing windows. It
requires both removal and shutdown refusal with exact hook/heap/block ownership,
source bytes and suspension accounting retained. Independent cases preserve
read/query/protection/budget failure refusal. Restoring only pointer-width
stepping must fail at `unaligned stack owner blocks removal before release`.

A new production-linked native x64/Win32 fixture uses an actual worker with
committed stack padding. It externally suspends that worker, saves context and
stack bytes, places the real published pointer at every alignment and across two
read boundaries, requires both refusals, restores the exact bytes, then resumes
and joins the worker before successful retirement. No target or original is
executed. Genuine Windows run
[43560037514](https://github.com/raleonys/mithrilhook/actions/runs/43560037514)
passes all seven cells on `8464e2733095992edf60b99805b80ffbdedab5de`: 273 native
Windows/package tests plus two portable tests, 178 real fixture checks per x64
cell and 94 per Win32 cell, and the exact stepping control on every cell. The
projected completion suite reports 10,104 x64 and 9,272 Win32 assertions.
Both shared cells pass 250 independent live-call processes each, 400,000 combined
transitions and 356,183,335 actual calls with zero bad results/residual handles.
Portable decoder/relocator sanitizers pass but do not execute this retirement path.

At this review stage VERSION was the unpublished owner-selected 1.0.3.
Packages prepared before the correction did not validate it. The public release
is 1.0.4; see the current release evidence linked above.

The same corrected source passed the full five-environment, eight-engine,
38-workload comparison in
[43560037534](https://github.com/raleonys/mithrilhook/actions/runs/43560037534):
10,640 positive children and five independent retained-evidence audits. Detailed
retirement and call timing distributions retain their exact source and host
identities; this is not a same-host before/after regression experiment or
application acceptance.
