# Byte-register aliases are misclassified by the unwind body filter

Status: confirmed predicate-level finding; runtime correction is not included
in this PR. Reviewed source: `97cc90c83a358a2420fe423fa909e2c34518a4c0`.

## Reproduction

`MthInternal_IsUnwindNeutralInstruction` maps encoded register numbers directly
to full general-purpose register numbers. Byte registers require different
interpretation: without a REX prefix, encodings 4..7 name AH/CH/DH/BH, while a
REX prefix selects SPL/BPL/SIL/DIL instead. BH aliases RBX; CH aliases RCX.

Calling the actual predicate from the reviewed source with the repository's
portable memory API projection produces:

| Instruction | Active frame register | Actual effect | Current neutral result |
| --- | --- | --- | --- |
| `B7 12` / `mov bh,12h` | RBX (3) | Changes the active RBX frame register | TRUE |
| `B5 12` / `mov ch,12h` | RBP (5) | Changes RCX, leaves RBP unchanged | FALSE |

The first result defeats the predicate's intended frame-register refusal.
The second is an unnecessary compatibility refusal. Both are reproduced at
the actual predicate boundary; an end-to-end Windows stack-unwind failure
from this case has not been demonstrated. The existing portable tests pass
without these alias cases.

## Affected paths and proposed follow-up

The byte forms in `src/trampoline.c` use raw ModR/M reg/rm values and opcode
register fields when applying `IsUnwindRegisterProtected`. Normalize aliases
with operand-size and REX awareness before checking protected RSP/frame
register effects. Audit immediate MOV, register MOV, SETcc, arithmetic,
exchange, shifts and byte unary operations; keep word/dword/qword mappings
separate. A correction must cover both reg and register-direct rm operands.

Acceptance should exercise AH/CH/DH/BH, their REX low-byte counterparts and
extended byte registers, with protected and unrelated frame registers.
Include legal positive controls rather than refusing every high-byte form.
Require unsafe frame changes to be refused and unrelated byte writes to retain
their compatibility. Run portable sanitizers and the native x64 unwind and
eleven-target compatibility suites; preserve all existing ownership checks.

No production source, public API, export or test fixture is changed here.
