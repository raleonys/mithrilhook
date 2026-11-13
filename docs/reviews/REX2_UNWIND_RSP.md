# REX2 SPL write bypasses the protected-RSP unwind check

Status: confirmed decoder/predicate contract mismatch; no runtime correction
is included in this review PR. Reviewed master:
`4994c7ee335737d8790d94cbab896d06f37618f5`.

## Reproduction and evidence

Compare the actual `MthInternal_IsUnwindNeutralInstruction` results with no
active frame register:

| Bytes | Instruction | HDE flags | hs.rex | Neutral result |
| --- | --- | --- | --- | --- |
| `40 B4 10` | `mov spl,10h` | `0x40000004` | `0x40` | FALSE |
| `D5 00 B4 10` | `{rex2 0x0} mov spl,10h` | `0x80000004` | `0` | TRUE |

GNU Binutils 2.44 independently disassembles the second form as an SPL write.
HDE accepts it with F_PREFIX_REX2 while hs.rex remains zero. The normalization
helper tests only hs.rex, so it maps byte encoding 4 to AH/RAX rather than
SPL/RSP. The protected-stack check consequently misses the RSP modification.

Both predicate results were reproduced with the actual decoder and trampoline
sources using the repository's portable memory API projection. The ordinary
REX control is correctly refused. PR #9's tested legacy high-byte and ordinary
REX fixes remain valid; REX2 is an additional prefix case.

## Scope limits

The REX2 instruction was not executed on APX hardware, and an end-to-end native
Windows unwind failure has not been demonstrated. This finding is relevant to
APX-capable targets and accepted APX byte streams; it is not evidence that an
ordinary current REX-only application target has failed. The reproduced defect
is the incorrect semantic classification at the predicate boundary.

## Requested follow-up

Either refuse unsupported REX2/APX forms at this boundary or propagate and
normalize the complete supported prefix/register-extension information before
applying protected-RSP/frame checks. Retain the raw ModR/M opcode-extension
selectors where they are not registers. Audit extended APX registers separately;
the legacy REX bits alone do not represent the complete REX2 register space.

Acceptance should include the two SPL controls, supported REX2 forms with
RSP/frame/ordinary destinations, extended-register positive controls and public
API refusal/ownership behavior. Keep decoder/predicate testing distinct from
execution on an identified APX host and genuine Windows unwind validation.

Only this review document and its source-inventory entry change in this PR.
Implementation and hardware/native lifecycle validation remain pending.
