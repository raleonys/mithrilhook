# Internal CALL targets inside the patch are not remapped

**Status: resolved and included in 1.0.4 (PR #18).** Copied internal CALL destinations are refused before publication.

This is a historical review record. The finding, reproductions, counts and
version decisions below refer to their stated development baselines. They are
not open defects or current publication instructions. Current contracts and
release evidence are in [API](../API.md), [Safety](../SAFETY.md),
[Validation](../VALIDATION.md) and [Release](../RELEASE.md).

## Review status

The initial report did not change the runtime engine. The correction and tests
were subsequently included in the same PR; the original observations remain below.
The finding was reproduced against `9f822317bcf3fa52a12683e0fbfaf1e28e3bcaee`,
the merge commit of PR #17 and current `master` at the time of review.

## Finding

`MthInternal_CreateTrampolineFunction` resolves relative JMP, Jcc and LOOP
destinations inside the five-byte patch through the completed instruction map.
A relative CALL is always expanded to an absolute call to its original virtual
destination. If that destination is an instruction boundary inside
`[target, target + 5)`, enabling the hook replaces the destination bytes with
the entry E9. The published original trampoline then calls into the E9
operand instead of its copied instruction.

The following bounded function uses only valid instruction boundaries:

```text
00: eb 02                 jmp  +4
02: c3                    ret          ; internal helper
03: 90                    nop
04: e8 f9 ff ff ff        call +2
09: b8 2a 00 00 00        mov  eax,42
0e: c3                    ret
```

Before patching, entry execution jumps to the call, the helper returns, and the
function returns 42. The first branch keeps decoding alive through the call
site, so hook creation accepts this layout. The generated trampoline contains
an absolute CALL whose embedded pointer is `target + 2`, not the corresponding
trampoline instruction. That source address is part of the subsequently
published five-byte patch.

This is not an overlapping-instruction program: offsets 0, 2, 3, 4, 9 and 14
are distinct decoded instruction boundaries.

## Independent observations

A structured x64 emulator run used the production relocator, executed the
published trampoline before and after replacing the source's first five bytes,
and produced:

```text
accepted: 1
absolute_call_target: source + 2
before_patch: rax=42, balanced return
after_patch: invalid memory read at source + 2
```

A separate public-API probe compiled the complete current engine with the
diagnostic Win32 projection and executed the generated code on the host x64
CPU. It did not edit the engine and produced:

```text
create=MTH_OK enable=MTH_OK
original_call_target=target+2
original() child_signal=11
disable=MTH_OK shutdown=MTH_OK
PROJECTED_RUNTIME_TABLES_REMAINING=0
```

The bounded child prevents the expected bad original-call path from terminating
the harness. Source restoration, shutdown and projected runtime-table cleanup
still completed, isolating the failure to relocation semantics rather than
cleanup ownership.

## Expected correction and acceptance

An accepted relative CALL destination inside the overwritten patch must resolve
through the same completed old-to-new instruction-boundary map as internal
branches, while retaining CALL return behavior. A destination in the middle of
an instruction must remain unsupported. If a correct bounded transformation
cannot be represented, creation must return `MTH_ERROR_UNSUPPORTED_FUNCTION`
without publishing `ppOriginal` or changing target bytes.

Acceptance should include genuine Windows x64 public-API execution of this
forward-entry/backward-helper layout before enable, through the enabled target,
through the original trampoline, and after disable. It should also cover every
internal CALL destination boundary in the five-byte patch, an unmapped-middle
negative control, source restoration, unwind registration/retirement and the
existing internal JMP/Jcc/LOOP matrix. A negative control should make the old
unmapped-CALL behavior fail so that simple acceptance without remapping cannot
satisfy the test.

## Correction in this PR

Refuse a copied relative CALL into [target,target+5) before original
publication on both x86 and x64, including valid instruction boundaries.
The existing internal branch mapping does not establish a general subroutine
return/unwind contract. Keeping this form explicitly unsupported avoids
publishing a CALL into source bytes that the hook will overwrite. Outside
relative calls keep their existing fixup; CALL-next, ambiguous 66 prefixes
and other conservative refusals remain intact.

An independent real Linux x64 CPU diagnostic with projected memory APIs
reproduced source/original returning 42 before the synthetic patch, with an
embedded CALL pointer to source+2. Its bounded post-patch child faulted with
SIGILL (the original reporter observed SIGSEGV). The corrected relocator
refuses the same layout. Neither fault is used as a passing negative control.
The unmodified official MinHook relative-CALL path also keeps the original
source destination; this is an inherited algorithm gap, not a PUSH fix
regression introduced by #17.

Portable ASan/UBSan coverage adds 1,040 layouts: 26 effective legacy/REX prefix
orders, five CALL sites and eight destinations covering the five overwritten
offsets, both exact outside boundaries and a remote callee. Ten additional
cases cover the exact forward entry and earlier Jcc expansion. The suite also
checks unchanged source bytes and exact outside-call pointers. All 11,790
relocator assertions pass locally. Against uncorrected source the new suite
must exit 1 at its specific CALL range assertion.

The native fixture starts with the exact valid source returning 42 and checks
refusal before any original execution or activation. It covers every patch
offset (mapped and unmapped), CALL sites, prefixes and preceding expansion,
unchanged output/code and absent hook ownership. Ordinary external CALLs then
exercise creation, original execution, enable/disable/removal and source/handle
restoration on x86/x64. A registered x64 forty-byte allocation control checks
source v1/generated v2 RtlVirtualUnwind before/after activation, exact caller
and stack recovery, and deletion of the generated function table on removal.
A native negative control removes only the new CALL guard and requires exit 1
at exactly `internal CALL refuses before original publication`; no fault or
timeout can satisfy it. Exact-head Windows run links are recorded in PR #18.

This finding blocked publication of that development candidate until the
correction and fresh native evidence were reviewed. Historical #17 timings/packages keep
their original source identity and do not validate this correction.
