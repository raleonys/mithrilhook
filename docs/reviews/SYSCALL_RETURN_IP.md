# Relocated SYSCALL exposes the trampoline return address

## Review status

The initial review was report-only. The correction and regression tests are
now included directly in this same PR. The
finding was reproduced against `644a69ffa393fe7cf030d802c3b5746c71568cf6`,
the merge commit of PR #19 and current `master` at the time of review.

## Finding

`SYSCALL` writes the address of its following instruction to RCX before
entering the kernel and returns through that address. MithrilHook currently
copies a `0F 05` instruction in the stolen prefix. The system call returns
correctly, but the published original leaves RCX containing a trampoline
address instead of the source continuation address.

The minimized host-x64 fixture is:

```text
00: 31 c0          xor eax,eax
02: b0 27          mov al,39       ; bounded Linux getpid service
04: 0f 05          syscall
06: 48 89 0f       mov [rdi],rcx   ; observe architectural return RIP
09: c3             ret
```

The relocator copies six bytes, including `SYSCALL`, then jumps back to the
source store. Both paths complete the same harmless system call and execute the
same store. Only the RCX value produced by `SYSCALL` differs.

## Independent public-API observation

The complete current engine was compiled with the diagnostic Win32 projection
and its generated code was executed on the host x64 CPU. No runtime source was
modified. The public path produced:

```text
create=MTH_OK enable=MTH_OK
target=0x7faffb4a0000 original=0x7faffb490f00
source RCX=0x7faffb4a0006      expected target+6
original RCX=0x7faffb490f06    expected trampoline+6
disable=MTH_OK shutdown=MTH_OK
PROJECTED_RUNTIME_TABLES_REMAINING=0
```

The source and original observations exactly match the architectural next RIP
for their respective instruction copies. Target restoration and shutdown
completed, isolating the mismatch to accepted relocation semantics rather than
patch or ownership cleanup.

## Scope

This is not the documented behavior of a relocated CALL exposing a different
return address to its callee: the copied function contains no CALL. It is also
not x87 state, RIP-relative data addressing, an internal branch, an injected
failure or an invalid instruction. `SYSCALL` is a valid user-mode x64
instruction on both the host and the Windows target architecture.

The Linux service number exists only to make the host execution bounded and
harmless. RCX next-RIP publication is defined by the x64 `SYSCALL` instruction,
not by that operating-system service. The Windows correction must be validated
on Windows rather than transferring the Linux service result into a Windows
system-call compatibility claim.

## Expected correction and acceptance

The engine must not publish an original whose accepted copied `SYSCALL` exposes
the trampoline continuation in place of the source continuation. A proved
transformation may restore every supported observable effect; otherwise hook
creation should return `MTH_ERROR_UNSUPPORTED_FUNCTION` without publishing
`ppOriginal` or changing target bytes.

A genuine Windows x64 acceptance fixture can read the service number from the
loaded `ntdll!NtYieldExecution` stub, then call an owned function with that
number already in EAX. Put three neutral bytes followed by `0F 05` in the exact
five-byte prefix, and use a source-resident RIP-relative store after offset 5
to capture RCX without relying on volatile registers across the service. The
test should compare source and original RCX, enabled-detour behavior, refusal
publication, source restoration and retirement. It must use a bounded
no-argument service and retain the existing CALL/x87 negative controls.

The policy review should also classify other copied privilege-transition or
exception-return instructions separately; their existence must not be used to
weaken the decisive `SYSCALL` reproducer.

## Correction and policy in this PR

Refuse copied SYSCALL before original publication on both architectures.
An unmodeled kernel transition is not transformed into a guessed RCX repair.
The policy separately refuses copied SYSRET, SYSENTER, SYSEXIT and RSM,
software interrupts/traps (INT/INT3/INTO/ICEBP), IRET and far CALL/JMP/RET.
Those privileged or architecture-specific forms are structural refusal tests
only, never executed. Ordinary near CALL/RET remain supported. This finite
policy is not a claim of full privileged-ISA emulation or screening.

An independent real Linux x64 CPU diagnostic, using the production relocator
and projected Windows memory APIs, reproduces source+6 versus trampoline+6
through the bounded getpid service. The corrected relocator refuses the exact
layout. These results do not claim genuine Windows execution of that Linux
service. Portable ASan/UBSan coverage adds 1,760 opcode/prefix/site layouts and
nine positive boundary/ordinary-instruction controls; all 20,436 relocator
assertions pass. Against uncorrected source the suite must exit 1 at exactly
`copied system transitions refuse before original publication`.

The native x64 public-API fixture reads a bounded NtYieldExecution service
number from the loaded ntdll stub, never hardcoding an OS build's identifier.
Owned source instructions perform only that no-argument service. An owned
ABI-valid wrapper loads EAX before entering the source; a RIP-relative source
store captures RCX without trusting a volatile output pointer across the gate.
Exact five-byte-prefix and other copied positions execute source first, then
require refusal with unchanged ppOriginal/code and no hook owner. Allowed
source-resident gates after an ordinary copied prefix retain the exact source
continuation before/after enable, detour bypass, disable and removal. Source
and wrapper runtime tables, executable storage and handles retire in order.
Native x86 checks structural refusals and ordinary lifecycle controls; it does
not execute a guessed native x86 service ABI. A generated guard-removal control
must exit 1 at exactly `transition instruction refuses before original
publication`, before an unsafe original can execute or be enabled. Existing
CALL/x87/unwind/retirement controls remain in the complete matrix.

## Version and publication

The owner selected version 1.0.2 for stable tag/release publication after these
checks. Canonical VERSION, numeric/full package/DLL metadata, stable CMake
requests, README/changelog and release documentation are updated together.
The prepared 1.0.1 was not tagged or published. Fresh exact-source Windows,
package and broad benchmark evidence is recorded in PR #20; earlier records
keep their actual source identities. Citrine integration remains the next
separate engineering phase.
