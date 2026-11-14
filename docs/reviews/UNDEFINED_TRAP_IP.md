# Copied undefined-instruction traps expose the trampoline exception address

## Review status

The correction refuses copied UD0/UD1/UD2 before original publication. The
finding was reproduced against `c60123e4c15c9be982e3b9238cef220a298d140b`,
the merge commit of PR #20 and current `master` at the time of review.

## Finding

PR #20 refuses copied software interrupt/trap instructions so a published
original does not move their architectural event from the source prefix to the
trampoline. Three deliberate undefined-instruction traps remain accepted:

```text
0f 0b       UD2
0f b9 c0    UD1 eax,eax
0f ff c0    UD0 eax,eax
```

MithrilHook's HDE implementation intentionally recognizes `UD2` as a
two-byte no-operand instruction and `UD1`/`UD0` as three-byte ModR/M
instructions. None carries `F_ERROR`. The trampoline policy has no matching
refusal, so each instruction is copied byte-for-byte and hook creation can
publish the relocated entry.

Unlike an accidental access violation, these opcodes are explicit,
architecturally guaranteed invalid-opcode traps. An exception or signal
observer therefore sees the source instruction address before relocation and
the trampoline instruction address through the published original.

## Actual host-x64 execution

A bounded diagnostic installed a `SIGILL` context handler, executed each
source instruction, advanced over the known instruction length, and then
executed the accepted trampoline. The current relocator and HDE sources were
compiled unchanged. All three cases completed after recording the event IP:

```text
UD2: accepted source_exception=source+0 original_exception=trampoline+0
UD1: accepted source_exception=source+0 original_exception=trampoline+0
UD0: accepted source_exception=source+0 original_exception=trampoline+0
```

The handler observed the exact address of the instruction that raised each
event. Source and trampoline had distinct addresses; no decoder failure,
unrelated crash or timeout was accepted as evidence.

An independent x64 flow-classification sweep of valid one-byte and legacy
`0F` exception/interrupt forms found the existing INT/INT1 cases refused. The
accepted exception-class results were confined to `UD0`, `UD1` and `UD2`,
including the decoded ModR/M forms. This bounds the report to the identified
policy omission rather than treating every privileged opcode as equivalent.

## Scope

This report does not claim general exception-address translation for every
instruction that can fault due to memory, privilege, machine state or the
execution environment. It closes a finite omission in the explicit copied-trap
policy introduced by PR #20. `UD0`, `UD1` and `UD2` are deliberate trap
instructions, directly analogous to the already refused INT/INT3/INTO/ICEBP
class for this policy decision.

The finding is independent of ordinary CALL return-address introspection,
which the API documents as outside the relocation contract. It also does not
depend on SYSCALL, x87 state, RIP-relative memory, an internal branch or a
privileged instruction.

## Expected correction and acceptance

The engine must not publish an original that copies these three explicit traps
under the current trap-refusal contract. Unless a complete exception-address
translation is provided, hook creation should return
`MTH_ERROR_UNSUPPORTED_FUNCTION` without changing `ppOriginal`, target bytes,
hook ownership or runtime-table ownership.

A genuine Windows x64 fixture should install a vectored exception handler on
owned generated code and verify `EXCEPTION_ILLEGAL_INSTRUCTION` plus the exact
source `ExceptionAddress` for each unhooked control. It should then require all
opcode, ModR/M, copied-offset and accepted legacy-prefix variants to refuse
before publication. Ordinary NOP/RET controls and trap instructions entirely
after the copied prefix must retain their existing behavior.

The negative control should remove only the new guard and require a failure at
the exact refusal assertion. Structural privileged cases, unrelated process
termination and a handler that does not observe the expected exception code
and address must not count as proof.

## Correction and verification

The strict relocator now rejects decoded `0F 0B`, `0F B9 /r` and `0F FF /r`
whenever their instruction starts inside the copied five-byte prefix. No decoder
recognition or public API is removed. The guard is independent of ModR/M
addressing and accepted prefixes. Traps entirely after that prefix stay at source.

The portable ASan/UBSan suite passes 143,571 relocation checks plus 112 decoder
checks. It covers every ModR/M byte, all five copied offsets, eight legacy-prefix
choices and all sixteen single REX prefixes, plus source-resident controls.

The new production-linked Windows fixture observes each canonical source trap
with a bounded vectored handler: only the exact owned address and
`EXCEPTION_ILLEGAL_INSTRUCTION` may resume. It exercises the refusal matrix and
executes source-resident traps through source and original entries before and
after enable/disable, with exact byte and handle restoration. Removing only the
new guard must exit 1 at `undefined trap refuses before original publication`,
before any unsafe original executes. Native results are pending validation.
