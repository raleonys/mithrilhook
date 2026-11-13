# Accepted call-next/pop idiom exposes a changed code address

Status: confirmed relocator semantic difference; no runtime correction is
included in this review PR. Reviewed master:
`4994c7ee335737d8790d94cbab896d06f37618f5`.

## Reproduction and evidence

Input: `E8 00 00 00 00 58 C3` (`call next; pop rax; ret`). The original
returns source+5. The emitted x64 CALL_ABS pushes trampoline+6, so the POP
returns that different address. The actual HDE/trampoline builder accepts it.

Executing the original and emitted trampoline on a genuine x64 CPU on Linux,
with the repository's portable memory API projection, reproduced:

```text
getpc accepted=1
original=source+5
trampoline=trampoline+6
ordinary_call_control original=42 trampoline=42
```

The ordinary control uses a relative CALL to a separate constant-returning
helper. Both source and trampoline return 42, isolating the get-PC idiom from
ordinary calls. The failing example observes the architectural return address
as data; matching instruction lengths alone does not preserve that behavior.

Affected path: the E8 rewrite in `src/trampoline.c`, which emits CALL_ABS without
a policy for observing the original return address. This is inherited behavior,
not a regression introduced by PR #9.

## Scope limits

The evidence demonstrates actual CPU instruction semantics with projected
memory boundaries. It does not establish a native Windows MTH_CreateHook
installation/retirement result or source-unwind admission for this custom
get-PC function. Consumer-provided code must still satisfy the documented
Windows ABI/unwind contract. Application impact depends on an actual target
containing this idiom. General return-address observation deserves an explicit
contract; this finding does not show that all relative CALL relocations fail.

## Requested follow-up

Either deliberately preserve the supported get-PC idiom's observable result,
or refuse it as unsupported before publishing the trampoline. Specify the
boundary for broader return-address observation. A rewrite must respect stack
effects, flags, unwind behavior and the applicable control-flow mitigations;
simply substituting PUSH/JMP is not an assumed solution.

Acceptance should retain the minimal source/trampoline address comparison,
ordinary CALL controls, signed/prefixed variants where supported, public-API
failure publication/cleanup checks and native x64 compiler/configuration runs.
Report refusal separately from semantic-preserving support.

Only this review document and its source-inventory entry change in this PR.
Implementation and native lifecycle validation remain pending.
