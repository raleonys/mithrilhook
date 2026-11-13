// SPDX-License-Identifier: GPL-3.0-only
// Genuine Windows runtime-function registration and virtual unwinding.
// Owned fixture instructions execute; invented return addresses are only unwound.
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

static void verify_generated_unwind(BYTE *pc,DWORD64 *sp,DWORD64 expectedRsp,DWORD64 expectedRip,DWORD64 expectedRbx,DWORD64 initialRbx)
{
    CONTEXT context;
    DWORD64 base,frame;
    PVOID handler;
    PRUNTIME_FUNCTION function=RtlLookupFunctionEntry((DWORD64)(ULONG_PTR)pc,&base,NULL);
    require(function!=NULL,"generated instruction range has an owned runtime function");
    memset(&context,0,sizeof(context));context.ContextFlags=CONTEXT_FULL;
    context.Rip=(DWORD64)(ULONG_PTR)pc;context.Rsp=(DWORD64)(ULONG_PTR)sp;context.Rbx=initialRbx;
    (void)RtlVirtualUnwind(0,base,context.Rip,function,&context,&handler,&frame,NULL);
    if(context.Rip!=expectedRip || context.Rsp!=expectedRsp || context.Rbx!=expectedRbx)
        fprintf(stderr,"UNWIND_DETAIL pc_offset=%llu range_start=%lu check=%u rip_match=%u rsp_delta=%lld rbx=%llu expected_rbx=%llu\n",
            (unsigned long long)((DWORD64)(ULONG_PTR)pc-base),(unsigned long)function->BeginAddress,checks,
            (unsigned)(context.Rip==expectedRip),(long long)(context.Rsp-expectedRsp),
            (unsigned long long)context.Rbx,(unsigned long long)expectedRbx);
    require(context.Rip==expectedRip && context.Rsp==expectedRsp && context.Rbx==expectedRbx,
        "generated unwind restores the exact caller stack, return address and nonvolatile register");
}

static void frame_case(BYTE *code,RUNTIME_FUNCTION *source,UINT kind)
{
    BOOL established=kind!=0;
    const BYTE early[]={0x55,0x48,0x89,0xe5,0xb8,7,0,0,0,0x5d,0xc3};
    const BYTE late[]={0x55,0x48,0x83,0xec,0x20,0x48,0x8d,0x6c,0x24,0x20,0xb8,7,0,0,0,0x48,0x83,0xc4,0x20,0x5d,0xc3};
    const BYTE earlyInfo[]={1,4,2,5,4,3,1,0x50};
    const BYTE lateInfo[]={1,10,3,0x25,10,3,5,0x32,1,0x50,0,0};
    const BYTE offsetCode[]={0x55,0x50,0x50,0x48,0x8d,0x6c,0x24,0x10,0xb8,7,0,0,0,0x48,0x83,0xc4,0x10,0x5d,0xc3};
    const BYTE offsetInfo[]={1,8,4,0x15,8,3,3,2,2,2,1,0x50};
    DWORD64 stack[16],base,frame;CONTEXT context;PVOID handler;
    PRUNTIME_FUNCTION found;LPVOID original=NULL;
    typedef int (WINAPI *FUNCTION)(void);
    memset(code,0x90,32);
    memcpy(code,kind==2?offsetCode:established?early:late,kind==2?sizeof(offsetCode):established?sizeof(early):sizeof(late));
    memcpy(code+256,kind==2?offsetInfo:established?earlyInfo:lateInfo,kind==2?sizeof(offsetInfo):established?sizeof(earlyInfo):sizeof(lateInfo));
    require(RtlAddFunctionTable(source,1,(DWORD64)(ULONG_PTR)code),"register source frame-pointer case");
    require(FlushInstructionCache(GetCurrentProcess(),code,32),"flush source frame-pointer case");
    require(MTH_Initialize()==MTH_OK,"initialize frame-pointer engine");
    require(MTH_CreateHook(code,code+64,&original)==MTH_OK,"publish bounded frame-pointer trampoline");
    memset(stack,0x55,sizeof(stack));stack[4]=0x22113344;stack[5]=0x12345678;
    memset(&context,0,sizeof(context));context.ContextFlags=CONTEXT_FULL;
    context.Rip=(DWORD64)(ULONG_PTR)((BYTE*)original+(kind==2?8:established?9:5));
    context.Rsp=(DWORD64)(ULONG_PTR)(kind==2?stack+2:established?stack+4:stack);
    context.Rbp=established?(DWORD64)(ULONG_PTR)(stack+4):0x88776655;
    found=RtlLookupFunctionEntry(context.Rip,&base,NULL);
    require(found!=NULL,"lookup synthetic frame-pointer jump-back range");
    (void)RtlVirtualUnwind(0,base,context.Rip,found,&context,&handler,&frame,NULL);
    require(context.Rip==stack[5]&&context.Rsp==(DWORD64)(ULONG_PTR)(stack+6)&&context.Rbp==stack[4],
        "frame established before/after prefix restores the exact caller frame");
    require(((FUNCTION)code)()==7&&((FUNCTION)original)()==7,"execute owned frame-pointer source and trampoline");
    require(MTH_RemoveHook(code)==MTH_OK&&MTH_Uninitialize()==MTH_OK,"retire frame-pointer table and code owners");
    require(RtlDeleteFunctionTable(source),"unregister source frame-pointer owner");
}

static void saved_state_case(BYTE *code,RUNTIME_FUNCTION *source,UINT kind)
{
    const BYTE nv[]={0x48,0x83,0xec,0x28,0x48,0x89,0x5c,0x24,0x20,0xb8,7,0,0,0,0x48,0x8b,0x5c,0x24,0x20,0x48,0x83,0xc4,0x28,0xc3};
    const BYTE xmm[]={0x48,0x83,0xec,0x18,0x0f,0x29,0x34,0x24,0xb8,7,0,0,0,0x0f,0x28,0x34,0x24,0x48,0x83,0xc4,0x18,0xc3};
    const BYTE large[]={0x48,0x81,0xec,8,1,0,0,0xb8,7,0,0,0,0x48,0x81,0xc4,8,1,0,0,0xc3};
    BYTE unwind[16]={1,0,0,0};
    BOOL wide=(kind&1)!=0;
    UINT category=kind/2,offset=category==0?9:category==1?8:7;
    UINT returnIndex=category==0?5:category==1?3:33;
    _Alignas(16) DWORD64 stack[64];DWORD64 base,frame;PVOID handler;CONTEXT context;
    LPVOID original=NULL;PRUNTIME_FUNCTION found;
    typedef int (WINAPI *FUNCTION)(void);
    memset(code,0x90,32);
    memcpy(code,category==0?nv:category==1?xmm:large,category==0?sizeof(nv):category==1?sizeof(xmm):sizeof(large));
    unwind[1]=(BYTE)offset;
    if(category<2)
    {
        UINT tail=wide?10:8;
        unwind[2]=wide?4:3;unwind[4]=(BYTE)offset;
        unwind[5]=(BYTE)(category==0?(wide?0x35:0x34):(wide?0x69:0x68));
        unwind[6]=(BYTE)(category==0?(wide?32:4):0);
        unwind[tail]=4;unwind[tail+1]=(BYTE)(category==0?0x42:0x22);
    }
    else
    {
        unwind[2]=wide?3:2;unwind[4]=7;unwind[5]=wide?0x11:1;
        unwind[6]=wide?8:33;unwind[7]=wide?1:0;
    }
    memcpy(code+256,unwind,sizeof(unwind));
    require(RtlAddFunctionTable(source,1,(DWORD64)(ULONG_PTR)code),"register saved-state source case");
    require(FlushInstructionCache(GetCurrentProcess(),code,32),"flush saved-state source case");
    require(MTH_Initialize()==MTH_OK&&MTH_CreateHook(code,code+64,&original)==MTH_OK,"publish saved-state trampoline metadata");
    memset(stack,0xa5,sizeof(stack));stack[returnIndex]=0x12345678;
    if(category==0)stack[4]=0x22113344;
    if(category==1){stack[0]=0x1122334455667788ULL;stack[1]=0x2233445566778899ULL;}
    memset(&context,0,sizeof(context));context.ContextFlags=CONTEXT_FULL;
    context.Rip=(DWORD64)(ULONG_PTR)((BYTE*)original+offset);context.Rsp=(DWORD64)(ULONG_PTR)stack;context.Rbx=0x55667788;
    found=RtlLookupFunctionEntry(context.Rip,&base,NULL);
    require(found!=NULL,"lookup saved-state synthetic jump-back metadata");
    (void)RtlVirtualUnwind(0,base,context.Rip,found,&context,&handler,&frame,NULL);
    require(context.Rip==stack[returnIndex]&&context.Rsp==(DWORD64)(ULONG_PTR)(stack+returnIndex+1),"saved-state unwind restores the exact caller return and stack");
    if(category==0)require(context.Rbx==stack[4],"scaled/unscaled nonvolatile save restores RBX");
    if(category==1)require(context.Xmm6.Low==stack[0]&&(DWORD64)context.Xmm6.High==stack[1],"scaled/unscaled XMM save restores all 128 bits");
    require(((FUNCTION)code)()==7&&((FUNCTION)original)()==7,"execute owned saved-state source and trampoline");
    require(MTH_RemoveHook(code)==MTH_OK&&MTH_Uninitialize()==MTH_OK,"retire saved-state generated owners");
    require(RtlDeleteFunctionTable(source),"unregister saved-state source owner");
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
    DWORD baseline, after;unsigned i;
    typedef int (WINAPI *OWNED_FUNCTION)(void);
    require(GetProcessHandleCount(GetCurrentProcess(), &baseline), "capture native unwind handle baseline");
    code = VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    require(code != NULL, "allocate native unwind fixture");
    memset(code,0x90,4096);memcpy(code,prologue,sizeof(prologue));
    code[64]=0xb8;code[65]=9;code[66]=code[67]=code[68]=0;code[69]=0xc3;
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
        if(found==NULL)
        {
            require(stack[0]!=stack[5], "legacy relocated prologue loses its source unwind entry");
            legacy=TRUE;
            require(MTH_RemoveHook(code)==MTH_OK, "negative control removes unpublished disabled hook");
        }
        else
        {
            verify_generated_unwind((BYTE*)original,stack+5,(DWORD64)(ULONG_PTR)(stack+6),stack[5],0x11223344,0x11223344);
            verify_generated_unwind((BYTE*)original+1,stack+4,(DWORD64)(ULONG_PTR)(stack+6),stack[5],stack[4],0x55667788);
            for(i=0;i<14;++i)
                verify_generated_unwind((BYTE*)original+5+i,stack,(DWORD64)(ULONG_PTR)(stack+6),stack[5],stack[4],0x55667788);
            require(((OWNED_FUNCTION)code)()==7 && ((OWNED_FUNCTION)original)()==7,"execute source and registered nonleaf trampoline");
            require(MTH_EnableHook(code)==MTH_OK && ((OWNED_FUNCTION)code)()==9 && ((OWNED_FUNCTION)original)()==7,
                "enabled owned target detours while its registered original executes correctly");
            require(MTH_DisableHook(code)==MTH_OK && ((OWNED_FUNCTION)code)()==7,"disable restores owned source behavior");
            require(MTH_RemoveHook(code)==MTH_OK,"remove owned generated unwind entries");
            require(RtlLookupFunctionEntry((DWORD64)(ULONG_PTR)((BYTE*)original+5),&base,NULL)==NULL,
                "retirement unregisters the generated runtime-function owner");
        }
    }
    else
    {
        require(FALSE,"supported stack-changing prologue must publish registered unwind metadata");
    }
    require(MTH_Uninitialize()==MTH_OK, "retire engine before unregistering source metadata");
    require(RtlDeleteFunctionTable(&function), "unregister first source unwind owner");
    if(!legacy)
    {
        frame_case(code,&function,1);frame_case(code,&function,0);frame_case(code,&function,2);
        for(i=0;i<6;++i)saved_state_case(code,&function,i);
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
        require(MTH_CreateHook(code,code+64,&original)==MTH_OK,
            "accept neutral prefix wholly inside a language-handler function's prologue");
        require(MTH_RemoveHook(code)==MTH_OK,"remove handler-prologue prefix owner");
        code[257]=0;code[258]=0; /* Handler-bearing body is outside the supported prologue subset. */
        require(MTH_CreateHook(code,code+64,&original)==MTH_ERROR_UNSUPPORTED_FUNCTION,
            "refuse handler-bearing body relocation without language-scope translation");
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
