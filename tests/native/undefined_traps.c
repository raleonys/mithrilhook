// SPDX-License-Identifier: GPL-3.0-only
#include <windows.h>
#include <MithrilHook.h>
#include <stdio.h>
#include <string.h>

typedef int (__cdecl *LEAF)(void);
static unsigned checks;
static BYTE *expectedTrap;
static UINT trapLength;
static volatile LONG observed;
static void require(BOOL ok,const char *why)
{++checks;if(!ok){fprintf(stderr,"FAIL: %s\n",why);ExitProcess(1);}}

/* Continue only the exact owned deliberate trap armed by this single-thread
 * fixture. Unexpected codes, addresses and repeated events remain unhandled. */
static LONG CALLBACK observe_trap(PEXCEPTION_POINTERS exception)
{
    ULONG_PTR ip;
#if defined(_M_X64) || defined(__x86_64__)
    ip=(ULONG_PTR)exception->ContextRecord->Rip;
#else
    ip=(ULONG_PTR)exception->ContextRecord->Eip;
#endif
    if(expectedTrap==NULL||observed!=0||
        exception->ExceptionRecord->ExceptionCode!=EXCEPTION_ILLEGAL_INSTRUCTION||
        exception->ExceptionRecord->ExceptionAddress!=expectedTrap||ip!=(ULONG_PTR)expectedTrap)
        return EXCEPTION_CONTINUE_SEARCH;
    observed=1;
#if defined(_M_X64) || defined(__x86_64__)
    exception->ContextRecord->Rip+=trapLength;
#else
    exception->ContextRecord->Eip+=trapLength;
#endif
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void execute_at(LPVOID entry,BYTE *trap,UINT length)
{
    expectedTrap=trap;trapLength=length;observed=0;
    require(((LEAF)entry)()==42,"bounded owned trap resumes at its known continuation");
    expectedTrap=NULL;
    require(observed==1,"Windows reports the exact source illegal-instruction address");
}

static void refuse(BYTE *source,BYTE *detour)
{
    BYTE snapshot[64];LPVOID original=(LPVOID)(ULONG_PTR)0x1234;
    memcpy(snapshot,source,sizeof(snapshot));
    require(MTH_CreateHook(source,detour,&original)==MTH_ERROR_UNSUPPORTED_FUNCTION,
        "undefined trap refuses before original publication");
    require(original==(LPVOID)(ULONG_PTR)0x1234&&!memcmp(source,snapshot,sizeof(snapshot)),
        "undefined-trap refusal preserves original output and source bytes");
    require(MTH_EnableHook(source)==MTH_ERROR_NOT_CREATED&&MTH_RemoveHook(source)==MTH_ERROR_NOT_CREATED,
        "undefined-trap refusal publishes no hook owner");
}

int main(void)
{
    const BYTE opcodes[]={0x0b,0xb9,0xff};
    const BYTE prefixes[]={0,0x66,0x67,0x2e,0xf2,0xf3,0x64,0x65};
    BYTE *area,*source,*detour;PVOID handler;DWORD before,after;UINT kind,prefix,site,modrm;
    require(GetProcessHandleCount(GetCurrentProcess(),&before),"capture undefined-trap handle baseline");
    area=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    require(area!=NULL,"allocate owned undefined-trap fixture");source=area+256;detour=area+512;
    memset(area,0x90,4096);detour[0]=0xb8;detour[1]=9;memset(detour+2,0,3);detour[5]=0xc3;
    handler=AddVectoredExceptionHandler(1,observe_trap);
    require(handler!=NULL,"install bounded source-address observer");
    require(MTH_Initialize()==MTH_OK,"initialize undefined-trap engine");
    for(kind=0;kind<3;++kind)
    {
        UINT length=kind?3:2;
        memset(source,0x90,64);source[0]=0x0f;source[1]=opcodes[kind];if(kind)source[2]=0xc0;
        source[length]=0xb8;source[length+1]=42;memset(source+length+2,0,3);source[length+5]=0xc3;
        require(FlushInstructionCache(GetCurrentProcess(),area,4096),"flush exact owned trap control");
        execute_at(source,source,length);
        /* The mutated engine must fail here with exit 1. An accepted unsafe
         * original is never invoked, and no crash can satisfy the oracle. */
        refuse(source,detour);
    }
    for(kind=0;kind<3;++kind)
    for(prefix=0;prefix<sizeof(prefixes);++prefix)
    for(site=0;site<5;++site)
    for(modrm=0;modrm<(kind?256U:1U);++modrm)
    {
        UINT n=site;memset(source,0x90,64);
        if(prefix)source[n++]=prefixes[prefix];
        source[n++]=0x0f;source[n++]=opcodes[kind];if(kind)source[n++]=(BYTE)modrm;
        source[24]=0xc3;refuse(source,detour);
    }
    for(kind=0;kind<3;++kind)
    for(site=5;site<10;++site)
    {
        UINT length=kind?3:2;BYTE snapshot[64];LPVOID original=NULL;
        memset(source,0x90,64);source[site]=0x0f;source[site+1]=opcodes[kind];if(kind)source[site+2]=0xc0;
        source[site+length]=0xb8;source[site+length+1]=42;memset(source+site+length+2,0,3);source[site+length+5]=0xc3;
        require(FlushInstructionCache(GetCurrentProcess(),source,64),"flush source-resident trap body");
        memcpy(snapshot,source,sizeof(snapshot));execute_at(source,source+site,length);
        require(MTH_CreateHook(source,detour,&original)==MTH_OK&&original!=NULL,"publish ordinary prefix before source-resident trap");
        execute_at(original,source+site,length);
        require(MTH_EnableHook(source)==MTH_OK,"enable source-resident trap control");
        observed=0;require(((LEAF)source)()==9&&observed==0,"enabled detour bypasses source-resident trap");
        execute_at(original,source+site,length);
        require(MTH_DisableHook(source)==MTH_OK&&!memcmp(source,snapshot,sizeof(snapshot)),"restore exact trap source bytes");
        execute_at(source,source+site,length);
        require(MTH_RemoveHook(source)==MTH_OK,"retire original before trap fixture storage");
    }
    {
        LPVOID original=NULL;memset(source,0x90,64);source[5]=0xb8;source[6]=42;memset(source+7,0,3);source[10]=0xc3;
        require(FlushInstructionCache(GetCurrentProcess(),source,64),"flush ordinary NOP/RET control");
        require(MTH_CreateHook(source,detour,&original)==MTH_OK&&((LEAF)original)()==42,"ordinary NOP/RET remains supported");
        require(MTH_EnableHook(source)==MTH_OK&&((LEAF)source)()==9&&((LEAF)original)()==42,"ordinary target and original execute correctly");
        require(MTH_RemoveHook(source)==MTH_OK&&((LEAF)source)()==42,"ordinary removal restores source execution");
    }
    require(MTH_Uninitialize()==MTH_OK,"retire all undefined-trap engine owners");
    require(RemoveVectoredExceptionHandler(handler)!=0,"remove source-address observer");
    require(VirtualFree(area,0,MEM_RELEASE),"release trap storage last");
    require(GetProcessHandleCount(GetCurrentProcess(),&after)&&after==before,"restore undefined-trap handle baseline");
    printf("PASS: %u native undefined-trap exception-address/refusal/lifecycle checks\n",checks);return 0;
}
