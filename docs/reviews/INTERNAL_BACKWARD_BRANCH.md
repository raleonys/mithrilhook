# Internal backward branch is not remapped after an earlier expansion

Reviewed master: `d6813fd1525ceb4907a20401d693569361853c0f` (merged PR #12).
This PR records the finding without a runtime correction. Diagnostic execution
used generated files under the review checkout's `build/` directory.

## Minimal accepted code

```text
offset  bytes          instruction
0       74 06          je source+8
2       FF C1          inc ecx
4       75 FA          jne source+0
6       90 90          nop; nop
8       B8 2A000000    mov eax,42
13      C3             ret
```

With ECX=0xFFFFFFFE and initial ZF=0, the source increments twice, exits the
loop and returns 42. It uses ordinary x64 instructions, changes no nonvolatile
registers, and performs no stack adjustment except the final RET.

The builder accepts this input. The first JE points outside the five-byte
patch interval and is expanded from 2 to 16 bytes. INC is copied at offset 16.
The backward JNE is copied at offset 18 with its old displacement -6, which
now targets trampoline+14, inside the preceding absolute-address data. The
correct internal destination would be trampoline+0.

The existing `pOldInst < jmpDest` length-change guard covers certain forward
spans. It does not repair/reject this backward branch following an earlier
instruction expansion. Both internal JMP and Jcc copying paths deserve review.
The inherited logic, not PR #9 or #12, causes the problem.

## Independent checks

Using the actual current HDE and trampoline C sources with the repository's
portable memory API projection:

- Unicorn x64 execution: original returned 42; trampoline faulted reading
  unmapped memory at trampoline+14.
- Actual Linux x64 CPU, each case in its own bounded child process with core
  dumps disabled: original returned 42 (exit 0); accepted trampoline faulted
  with SIGSEGV (exit -11).
- Positive control: replace the initial JE with two NOPs, leaving the same
  INC/backward-JNE loop. Original and trampoline both returned 42 (exit 0).

`build/internal_branch_probe.c` is the actual-CPU reproduction. A short wrapper
sets ECX, clears RAX, initializes flags with TEST ECX,ECX and calls the chosen
entry with balanced stack reservation. No unknown/APX instructions execute.
These are actual CPU results with projected memory API boundaries, not a
native Windows hook-enable/disable/unwind lifecycle test. Actual application
impact depends on its target entry containing this control-flow pattern.

## Required correction scope

Plan internal branch destinations using an old-to-new instruction map, fix up
their displacements after layout, or reject cases that cannot be represented
correctly. A branch to an invalid/unmapped instruction boundary must not be
silently accepted. Keep support for the plain backward-loop positive control.

Regression coverage should include prior Jcc/CALL expansions, internal forward
and backward JMP/Jcc targets, taken/not-taken conditions, source/trampoline CPU
results and native Windows creation/publication/cleanup behavior. An explicit
unsupported refusal is distinct from full relocation support.

Implementation and native Windows lifecycle validation remain pending.
This PR changes only this document and its source-inventory entry.

## Linux CPU reproduction source

Save the following as `build/internal_branch_probe.c`, then compile the actual
repository decoder/trampoline with the existing projected memory API:

```sh
gcc -std=c17 -O0 -g -Wall -Wextra -Werror -Itests/portable -Isrc \
  build/internal_branch_probe.c tests/portable/windows_stub.c \
  src/trampoline.c src/hde/hde64.c -o build/internal_branch_probe
```

Run each mode in a separate child process with a timeout. Expected observations:
`expanded-original`, `plain-original` and `plain-trampoline` return 42/exit 0;
`expanded-trampoline` is accepted and faults. A crash is evidence of this
unfixed defect, not a passing production regression test.

```c
/* Review-only native Linux x64 execution of the actual trampoline output. */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include "trampoline.h"
int main(int argc,char **argv)
{
 struct rlimit no_core={0,0};setrlimit(RLIMIT_CORE,&no_core);
 BYTE *area=VirtualAlloc(NULL,8192,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
 const BYTE loop[]={0x74,6,0xff,0xc1,0x75,0xfa,0x90,0x90,0xb8,42,0,0,0,0xc3};
 TRAMPOLINE ct;
 if(!area || argc!=2)return 2;
 memset(area,0x90,8192);memcpy(area+64,loop,sizeof loop);
 if(!strcmp(argv[1],"plain-original") || !strcmp(argv[1],"plain-trampoline"))
     area[64]=area[65]=0x90;
 memset(&ct,0,sizeof ct);ct.pTarget=area+64;ct.pTrampoline=area+512;ct.pDetour=area+1024;
 int accepted=MthInternal_CreateTrampolineFunction(&ct);
 printf("%s accepted=%d\n",argv[1],accepted);fflush(stdout);
 if(!accepted)return 3;
 uintptr_t target=(uintptr_t)(strstr(argv[1],"trampoline")?ct.pTrampoline:ct.pTarget);
 const BYTE prefix[]={0x48,0x83,0xec,0x28,0xb9,0xfe,0xff,0xff,0xff,0x31,0xc0,0x85,0xc9,0x49,0xbb};
 const BYTE suffix[]={0x41,0xff,0xd3,0x48,0x83,0xc4,0x28,0xc3};
 memcpy(area+2048,prefix,sizeof prefix);memcpy(area+2048+sizeof prefix,&target,8);
 memcpy(area+2048+sizeof prefix+8,suffix,sizeof suffix);
 uintptr_t base=(uintptr_t)area&~(uintptr_t)4095;
 size_t span=(((uintptr_t)area+8192-base)+4095)&~(size_t)4095;
 if(mprotect((void*)base,span,PROT_READ|PROT_WRITE|PROT_EXEC))return 4;
 int result=((int(*)(void))(area+2048))();
 printf("%s CPU_result=%d\n",argv[1],result);
 VirtualFree(area,0,MEM_RELEASE);
 return result==42?0:1;
}
```
