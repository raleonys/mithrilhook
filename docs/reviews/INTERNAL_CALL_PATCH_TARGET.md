# Internal CALL targets inside the patch are not remapped

## Review status

This is a report-only review. It does not change the runtime engine. The
finding was reproduced against `9f822317bcf3fa52a12683e0fbfaf1e28e3bcaee`,
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
