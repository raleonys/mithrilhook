// SPDX-License-Identifier: GPL-3.0-only
// Genuine Windows runtime-function registration and virtual unwinding.
// No fixture instructions or invented return addresses are executed.
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <MithrilHook.h>

static unsigned checks;
static void require(BOOL ok, const char *why)
{
    ++checks;
    if (!ok) { fprintf(stderr, "FAIL: %s\n", why); ExitProcess(1); }
}

int main(void)
{
    BYTE *code;
    const BYTE prologue[] = {0x53,0x48,0x83,0xec,0x20,0x90,0xb8,7,0,0,0,0x48,0x83,0xc4,0x20,0x5b,0xc3};
    const BYTE unwind[] = {1,5,2,0,5,0x32,1,0x30};
    RUNTIME_FUNCTION function = {0,32,256};
    PRUNTIME_FUNCTION found;
    DWORD64 base, frame;
    PVOID handler;
    DWORD64 stack[16];
    CONTEXT context;
    LPVOID original = (LPVOID)(ULONG_PTR)0x1234;
    MTH_STATUS result;
    BOOL legacy = FALSE;
    DWORD baseline, after;
    require(GetProcessHandleCount(GetCurrentProcess(), &baseline), "capture native unwind handle baseline");
    code = VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    require(code != NULL, "allocate native unwind fixture");
    memset(code,0x90,4096);memcpy(code,prologue,sizeof(prologue));code[64]=0xc3;
    memcpy(code+256,unwind,sizeof(unwind));
    require(FlushInstructionCache(GetCurrentProcess(),code,4096), "flush owned native unwind fixture");
    require(RtlAddFunctionTable(&function,1,(DWORD64)(ULONG_PTR)code), "register original runtime function");
    found=RtlLookupFunctionEntry((DWORD64)(ULONG_PTR)(code+5),&base,NULL);
    require(found!=NULL && base==(DWORD64)(ULONG_PTR)code, "lookup real source unwind entry");
    memset(stack,0x55,sizeof(stack));stack[4]=0x11223344;stack[5]=0x12345678;
    memset(&context,0,sizeof(context));context.ContextFlags=CONTEXT_FULL;
    context.Rip=(DWORD64)(ULONG_PTR)(code+5);context.Rsp=(DWORD64)(ULONG_PTR)stack;
    (void)RtlVirtualUnwind(0,base,context.Rip,found,&context,&handler,&frame,NULL);
    require(context.Rip==stack[5] && context.Rsp==(DWORD64)(ULONG_PTR)(stack+6) && context.Rbx==stack[4],
        "original metadata restores return address, stack and nonvolatile register");
    require(MTH_Initialize()==MTH_OK, "initialize native unwind engine");
    result=MTH_CreateHook(code,code+64,&original);
    if(result==MTH_OK)
    {
        /* This exact path is required by the guard-removal negative control. */
        found=RtlLookupFunctionEntry((DWORD64)(ULONG_PTR)((BYTE*)original+5),&base,NULL);
        require(found==NULL && stack[0]!=stack[5], "legacy relocated prologue loses its source unwind entry");
        legacy=TRUE;
        require(MTH_RemoveHook(code)==MTH_OK, "negative control removes unpublished disabled hook");
    }
    else
    {
        require(result==MTH_ERROR_UNSUPPORTED_FUNCTION && original==(LPVOID)(ULONG_PTR)0x1234,
            "refuse stack-changing relocated prologue without publishing original");
        require(!memcmp(code,prologue,sizeof(prologue)), "unwind refusal preserves source instructions");
        require(MTH_RemoveHook(code)==MTH_ERROR_NOT_CREATED, "unwind refusal publishes no hook owner");
    }
    require(MTH_Uninitialize()==MTH_OK, "retire engine before unregistering source metadata");
    require(RtlDeleteFunctionTable(&function), "unregister first source unwind owner");
    if(!legacy)
    {
        /* Five neutral NOPs precede all prologue operations. Their trampoline
         * remains leaf-unwindable before returning to registered source code. */
        memset(code,0x90,32);memcpy(code+5,prologue,sizeof(prologue));
        memcpy(code+256,unwind,sizeof(unwind));code[257]=10;code[260]=10;code[262]=6;
        require(RtlAddFunctionTable(&function,1,(DWORD64)(ULONG_PTR)code), "register neutral-prefix source");
        require(MTH_Initialize()==MTH_OK, "initialize neutral-prefix engine");
        require(MTH_CreateHook(code,code+64,&original)==MTH_OK && original!=NULL,
            "accept registered function whose relocated prefix precedes every unwind operation");
        stack[0]=0x12345678;
        memset(&context,0,sizeof(context));context.ContextFlags=CONTEXT_FULL;
        context.Rip=(DWORD64)(ULONG_PTR)(code+4);context.Rsp=(DWORD64)(ULONG_PTR)stack;
        found=RtlLookupFunctionEntry(context.Rip,&base,NULL);
        require(found!=NULL, "lookup neutral-prefix source metadata");
        (void)RtlVirtualUnwind(0,base,context.Rip,found,&context,&handler,&frame,NULL);
        require(context.Rip==stack[0] && context.Rsp==(DWORD64)(ULONG_PTR)(stack+1),
            "neutral prefix agrees with the leaf-unwind stack contract");
        require(MTH_RemoveHook(code)==MTH_OK, "remove supported neutral-prefix hook");
        original=(LPVOID)(ULONG_PTR)0x1234;
        require(MTH_CreateHook(code+1,code+64,&original)==MTH_ERROR_UNSUPPORTED_FUNCTION &&
            original==(LPVOID)(ULONG_PTR)0x1234, "refuse interior entry of a registered nonleaf function");
        code[256]=9; /* UNW_FLAG_EHANDLER, with a bounded dummy handler RVA. */
        {DWORD handlerRva=64;memcpy(code+264,&handlerRva,sizeof(handlerRva));}
        require(MTH_CreateHook(code,code+64,&original)==MTH_ERROR_UNSUPPORTED_FUNCTION,
            "refuse language-handler relocation without scope translation");
        require(MTH_Uninitialize()==MTH_OK, "retire neutral-prefix engine");
        require(RtlDeleteFunctionTable(&function), "unregister neutral-prefix metadata");
    }
    require(VirtualFree(code,0,MEM_RELEASE), "release source allocation after all owners retire");
    require(GetProcessHandleCount(GetCurrentProcess(),&after) && after==baseline, "native unwind fixture restores handle baseline");
    if(legacy)
    {
        puts("UNWIND_MISMATCH: relocated stack-changing prologue has no registered function entry");
        puts("UNWIND_CLEANUP: PASS hook, function table, allocation and handles retired");
        return 42;
    }
    printf("PASS: %u genuine runtime-function and unwind checks\n",checks);
    return 0;
}
