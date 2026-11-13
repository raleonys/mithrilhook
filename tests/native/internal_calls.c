// SPDX-License-Identifier: GPL-3.0-only
#include <windows.h>
#include <MithrilHook.h>
#include <stdio.h>
#include <string.h>

typedef int (__cdecl *FUNCTION)(void);
static unsigned checks;
static void require(BOOL ok,const char *why)
{++checks;if(!ok){fprintf(stderr,"FAIL: %s\n",why);ExitProcess(1);}}

static void refuse(BYTE *source,BYTE *detour)
{
    BYTE snapshot[128];LPVOID original=(LPVOID)(ULONG_PTR)0x1234;
    memcpy(snapshot,source,sizeof(snapshot));
    require(MTH_CreateHook(source,detour,&original)==MTH_ERROR_UNSUPPORTED_FUNCTION,
        "internal CALL refuses before original publication");
    require(original==(LPVOID)(ULONG_PTR)0x1234&&!memcmp(source,snapshot,sizeof(snapshot)),
        "internal CALL refusal preserves original output and all source bytes");
    require(MTH_EnableHook(source)==MTH_ERROR_NOT_CREATED&&MTH_RemoveHook(source)==MTH_ERROR_NOT_CREATED,
        "internal CALL refusal leaves no enabled or reserved hook owner");
}

#if defined(_M_X64) || defined(__x86_64__)
static void marker(void) {}
static void unwind(BYTE *pc,UINT version)
{
    _Alignas(16) DWORD64 stack[8];DWORD64 base,frame;PVOID handler;CONTEXT context;
    PRUNTIME_FUNCTION function=RtlLookupFunctionEntry((DWORD64)(ULONG_PTR)pc,&base,NULL);
    require(function!=NULL,"ordinary CALL retains an owned runtime function");
    require((*(const BYTE*)(ULONG_PTR)(base+function->UnwindData)&7)==version,
        "ordinary CALL source v1 and generated v2 metadata remain distinct");
    memset(stack,0,sizeof(stack));stack[5]=(DWORD64)(ULONG_PTR)marker;
    memset(&context,0,sizeof(context));context.ContextFlags=CONTEXT_FULL;
    context.Rip=(DWORD64)(ULONG_PTR)pc;context.Rsp=(DWORD64)(ULONG_PTR)stack;
    (void)RtlVirtualUnwind(0,base,context.Rip,function,&context,&handler,&frame,NULL);
    require(context.Rip==stack[5]&&context.Rsp==(DWORD64)(ULONG_PTR)(stack+6),
        "ordinary CALL unwind restores the exact caller and stack");
}

static void registered_call(BYTE *area,BYTE *source,BYTE *detour)
{
    const BYTE body[]={0x48,0x83,0xec,0x28,0xe8,55,0,0,0,0x48,0x83,0xc4,0x28,0xc3};
    const BYTE info[]={1,4,1,0,4,0x42,0,0};
    const BYTE helper[]={0xb8,42,0,0,0,0xc3};
    RUNTIME_FUNCTION function={256,270,2048};BYTE snapshot[128];LPVOID original=NULL;
    DWORD64 base;
    memset(source,0x90,128);memcpy(source,body,sizeof(body));memcpy(source+64,helper,sizeof(helper));
    memcpy(area+2048,info,sizeof(info));memcpy(snapshot,source,sizeof(snapshot));
    require(RtlAddFunctionTable(&function,1,(DWORD64)(ULONG_PTR)area),"register ABI-valid ordinary CALL with forty-byte allocation");
    require(FlushInstructionCache(GetCurrentProcess(),area,4096),"flush registered ordinary CALL");
    require(((FUNCTION)source)()==42,"registered CALL source executes independently");
    unwind(source+9,1);
    require(MTH_CreateHook(source,detour,&original)==MTH_OK&&original!=NULL,"publish registered ordinary CALL original");
    require(((FUNCTION)original)()==42,"registered CALL original returns correct helper result");
    unwind((BYTE*)original+4,2);unwind((BYTE*)original+20,2);
    require(MTH_EnableHook(source)==MTH_OK&&((FUNCTION)source)()==9&&((FUNCTION)original)()==42,
        "registered CALL target and original remain correct while enabled");
    unwind((BYTE*)original+20,2);
    require(MTH_DisableHook(source)==MTH_OK&&!memcmp(source,snapshot,sizeof(snapshot)),"restore registered CALL bytes");
    require(MTH_RemoveHook(source)==MTH_OK,"retire registered CALL generated owner");
    require(RtlLookupFunctionEntry((DWORD64)(ULONG_PTR)original,&base,NULL)==NULL,
        "removed CALL original has no surviving generated runtime table");
    require(((FUNCTION)source)()==42&&RtlDeleteFunctionTable(&function),"retire source metadata after CALL original retirement");
}
#endif

int main(void)
{
    const BYTE report[]={0xeb,2,0xc3,0x90,0xe8,0xf9,0xff,0xff,0xff,0xb8,42,0,0,0,0xc3};
    const BYTE prefixes[]={0,0x2e,0x67};
    BYTE *area,*source,*detour;DWORD before,after;UINT site,target,prefix;
    require(GetProcessHandleCount(GetCurrentProcess(),&before),"capture internal CALL handle baseline");
    area=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    require(area!=NULL,"allocate owned internal CALL fixture");source=area+256;detour=area+1024;
    memset(area,0x90,4096);detour[0]=0xb8;detour[1]=9;memset(detour+2,0,3);detour[5]=0xc3;
    require(MTH_Initialize()==MTH_OK,"initialize internal CALL engine");
    memcpy(source,report,sizeof(report));
    require(FlushInstructionCache(GetCurrentProcess(),area,4096),"flush exact internal CALL report");
    require(((FUNCTION)source)()==42,"exact report source returns forty-two before any hook publication");
    /* This is also the negative control's first oracle: it fails before an
     * unsafe original is ever executed or the entry patch is enabled. */
    refuse(source,detour);
    for(prefix=0;prefix<sizeof(prefixes);++prefix)
    for(site=0;site<5;++site)
    for(target=0;target<5;++target)
    {
        UINT size=prefix?1:0;INT32 displacement=(INT32)target-(INT32)(site+size+5);
        memset(source,0x90,128);if(size)source[site]=prefixes[prefix];
        source[site+size]=0xe8;memcpy(source+site+size+1,&displacement,4);source[site+size+5]=0xc3;
        refuse(source,detour);
    }
    /* Includes every real boundary in the entry patch (and unmapped middle
     * bytes). Only the independently validated exact source is executed. */
    for(prefix=0;prefix<sizeof(prefixes);++prefix)
    for(target=0;target<5;++target)
    {
        UINT size=prefix?1:0;INT32 displacement=(INT32)target-(INT32)(9+size);
        memset(source,0x90,128);source[0]=0x74;source[1]=30;
        if(size)source[4]=prefixes[prefix];
        source[4+size]=0xe8;memcpy(source+5+size,&displacement,4);
        refuse(source,detour);
    }
    for(prefix=0;prefix<sizeof(prefixes);++prefix)
    for(site=0;site<5;++site)
    {
        UINT size=prefix?1:0,end=site+size+5;INT32 displacement=64-(INT32)end;
        BYTE snapshot[128];LPVOID original=NULL;
        memset(source,0x90,128);if(size)source[site]=prefixes[prefix];source[site+size]=0xe8;
        memcpy(source+site+size+1,&displacement,4);source[end]=0xb8;source[end+1]=42;
        memset(source+end+2,0,3);source[end+5]=source[64]=0xc3;memcpy(snapshot,source,sizeof(snapshot));
        require(FlushInstructionCache(GetCurrentProcess(),area,4096),"flush outside CALL control");
        require(((FUNCTION)source)()==42,"outside CALL source returns independent expected result");
        require(MTH_CreateHook(source,detour,&original)==MTH_OK&&original!=NULL,"outside CALL remains supported after refusals");
        require(((FUNCTION)original)()==42&&!memcmp(source,snapshot,sizeof(snapshot)),"outside CALL original preserves result and source");
        require(MTH_EnableHook(source)==MTH_OK&&((FUNCTION)source)()==9&&((FUNCTION)original)()==42,
            "enabled outside CALL retains separate target and original behavior");
        require(MTH_DisableHook(source)==MTH_OK&&!memcmp(source,snapshot,sizeof(snapshot)),"restore outside CALL bytes");
        require(MTH_RemoveHook(source)==MTH_OK&&((FUNCTION)source)()==42,"retire outside CALL owner and execute restored source");
    }
#if defined(_M_X64) || defined(__x86_64__)
    registered_call(area,source,detour);
#endif
    require(MTH_Uninitialize()==MTH_OK,"complete internal CALL engine cleanup");
    require(VirtualFree(area,0,MEM_RELEASE),"release internal CALL source after all owners retire");
    require(GetProcessHandleCount(GetCurrentProcess(),&after)&&after==before,"restore internal CALL handle baseline");
    printf("PASS: %u native internal CALL refusal/ordinary execution/unwind/retirement checks\n",checks);return 0;
}
