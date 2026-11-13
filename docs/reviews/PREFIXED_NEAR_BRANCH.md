# Accepted operand-size-prefixed branch changes its destination

Status: confirmed finding; runtime correction is not included in this PR.
Reviewed source: `97cc90c83a358a2420fe423fa909e2c34518a4c0`.

## Reproduction

The target begins with `66 E9 05 00 00 00`. HDE64 consumes four bytes,
reports a relative immediate of five, and the trampoline accepts the
instruction. It emits a destination of target+9. Intel x64 consumes six bytes
and the original destination is target+11.

A controlled target places a short branch at target+9 leading to a function
returning 17, and places a function returning 42 at target+11. Compiling the
actual source decoder and trampoline builder with the repository's portable
memory API projection and executing the emitted bytes on a GenuineIntel x64
Linux CPU produced:

```text
accepted=1 hde_length=4 flags=0x4000208
emitted_destination=target+9
Intel_destination=target+11
original=42 trampoline=17
```

This is actual CPU semantic evidence with projected memory API boundaries.
It is not native Windows hook installation, suspension or teardown evidence.
The existing two portable sanitizer tests passed without detecting this case.
Iced-x86 1.21.0 independently decodes the same bytes at IP 0x10000 as:

```text
Intel: jmp near ptr 000000000001000Bh, length 6
AMD:   jmp near ptr 9, length 4
```

The AMD interpretation also needs its destination-width semantics; copying a
four-byte decode into an ordinary 64-bit-relative rewrite does not solve it.
The issue comes from the shared MinHook/HDE lineage.

## Affected paths and proposed follow-up

- `src/hde/hde64.c`: the C_IMM_P66/C_REL32 path consumes an imm16 under 66.
- `src/trampoline.c`: the accepted decode is used to calculate the destination
  without an architecture-specific operand-width policy.

Reject ambiguous 66-prefixed near CALL/JMP/Jcc forms before publishing a
trampoline, or implement and validate vendor-specific decode and destination
semantics. Keep ordinary branches and x86 behavior covered separately.

Acceptance should include the minimal JMP reproduction, near CALL and every
near Jcc condition, prefix combinations, negative displacements and ordinary
unprefixed controls. Require exact destination/result preservation or explicit
unsupported refusal. Run the x64 native compiler/configuration matrix and keep
the existing eleven-target compatibility probe and owner-cleanup checks.

No production source, public API, export or test fixture is changed here.
