# Operand-size precedence underestimates a RIP-relative PUSH access

**Status: resolved and included in 1.0.4 (PR #17).** Effective REX.W precedence is included in the proven PUSH memory range.

This is a historical review record. The finding, reproductions, counts and
version decisions below refer to their stated development baselines. They are
not open defects or current publication instructions. Current contracts and
release evidence are in [API](../API.md), [Safety](../SAFETY.md),
[Validation](../VALIDATION.md) and [Release](../RELEASE.md).

Reviewed master: `c02605cb041034c3158abd0f5974f3b564657e71` (merged PR #16).
The initial report recorded the finding before its runtime correction. Generated diagnostic
sources and binaries remained under the review checkout's ignored `build/`
directory.

## Accepted instruction and true range

The first instruction was:

```text
66 48 FF 35 F1 FF FF FF    push qword ptr [rip-15]
```

Both independent Intel and AMD iced-x86 decode modes identify an eight-byte
memory operand. REX.W takes precedence over the legacy operand-size prefix for
this form. With the instruction at `target`, the accessed half-open interval is
`[target-7, target+1)`, so its last byte is the first byte later replaced by the
five-byte hook jump.

`RipMemoryAccessSize` currently handles `FF /6` as two bytes whenever `p_66` is
present, without first applying REX.W. It therefore models only
`[target-7, target-5)`, considers the operand disjoint from the patch and
accepts relocation.

## Public-path reproduction

The executable source used the following balanced body:

```text
target-7  01 02 03 04 05 06 07
target+0  66 48 FF 35 F1 FF FF FF    push qword ptr [target-7]
target+8  48 8B 04 24                mov rax,[rsp]
target+12 48 83 C4 08                add rsp,8
target+16 C3                         ret
```

A version-1 source runtime entry described the completed eight-byte prologue
with `UWOP_ALLOC_SMALL(8)` at code offset 8. The exact current hook, buffer,
trampoline and HDE sources accepted it through `MTH_CreateHook`, registered
version-2 generated unwind metadata for the original trampoline and returned
`MTH_OK` from create, enable, disable, remove and uninitialize.

Actual Linux x64 CPU execution with the projected Windows allocation,
runtime-table and no-peer boundaries produced:

```text
source before enable:   0x6607060504030201
original before enable: 0x6607060504030201
enabled target:         0x0000000000000009
original after enable:  0xe907060504030201
generated unwind:       version 2
```

The trampoline keeps the original absolute memory address. Publishing the
target's `E9` changes the eighth byte read by the relocated PUSH from `66` to
`E9`, so the accepted original no longer preserves source behavior.

## Independent search boundary

A bounded oracle generated 196,608 legacy, VEX, XOP and EVEX layouts and found
31,088 unique independently valid RIP-relative memory forms. It checked 30,020
nominal self-overlaps and 29,984 one-byte boundary overlaps against the actual
current trampoline builder. This REX.W plus operand-size-prefixed PUSH was the
only accepted overlap found.

A separate expanded decoder comparison covered 9,568,256 layouts with
7,368,356 independently valid Intel/AMD-agreed forms and found no successful
HDE length mismatch. The expanded unwind-effect comparison checked the same
9,568,256 layouts, including 724,048 protected-register cases, and found no
instruction accepted as neutral while writing RSP or the active nonvolatile
frame register. Those negative results do not prove arbitrary ISA completeness.

The CPU and generated-registry evidence is real, but the Windows APIs are
projected. Genuine Windows `RtlVirtualUnwind`, public hook publication and
execution for this exact registered source remain required before claiming a
native Windows reproduction.

## Required correction scope

Apply the architectural operand-size precedence for `FF /6`: REX.W selects an
eight-byte memory read even when `66` is also present; otherwise `66` selects
two bytes and the x64 default is eight. Refuse this exact boundary overlap
before original-pointer publication while preserving proven disjoint controls.

Regression coverage should include all REX.W/66 prefix orders, PUSH r/m16 and
PUSH r/m64 controls, overlap at both range boundaries, source/original results,
unchanged refusal outputs, generated unwind registration, genuine Windows
virtual unwind and complete publication/retirement cleanup.

The historical finding above is preserved. The subsequent implementation corrects effective
REX.W precedence and adds prefix-order/range controls plus genuine Windows
source/generated metadata lookup, virtual unwind, execution and retirement
checks. Exact candidate revisions and completed runs are recorded in the PR
description; the original projected-API evidence is not relabeled as native.
