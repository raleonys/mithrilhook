// SPDX-License-Identifier: GPL-3.0-only
#include <windows.h>
#include <MithrilHook.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef void (__cdecl *FUNCTION)(void*);
static unsigned checks;
static void require(BOOL ok,const char *why)
{++checks;if(!ok){fprintf(stderr,"FAIL: %s\n",why);ExitProcess(1);}}

/* Keep the complete caller FP/SIMD state around each owned-code invocation.
 * Both architectures pass the output buffer to the fixture in ECX/RCX. The
 * wrapper seeds a balanced x87 operation at a fixed, unrelocated address. */
static void invoke(BYTE *area,LPVOID entry,BYTE *output,BYTE *backup)
{
    _Alignas(16) BYTE post[512],restored[512];
    BYTE code[128];UINT n=0;ULONG_PTR state=(ULONG_PTR)backup,function=(ULONG_PTR)entry;
    ULONG_PTR postAddress=(ULONG_PTR)post,restoredAddress=(ULONG_PTR)restored;
#if defined(_M_X64) || defined(__x86_64__)
    const BYTE begin[]={0x48,0x83,0xec,0x28,0x49,0xbb};
    const BYTE save[]={0x41,0x0f,0xae,0x03,0xd9,0xee,0xdd,0xd8,0x48,0xb8};
    const BYTE call[]={0xff,0xd0,0x49,0xbb};
    const BYTE capture[]={0x41,0x0f,0xae,0x03,0x49,0xbb};
    const BYTE restore[]={0x41,0x0f,0xae,0x0b,0x49,0xbb};
    const BYTE end[]={0x41,0x0f,0xae,0x03,0x48,0x83,0xc4,0x28,0xc3};
#else
    const BYTE begin[]={0x8b,0x4c,0x24,0x04,0xba};
    const BYTE save[]={0x0f,0xae,0x02,0xd9,0xee,0xdd,0xd8,0xb8};
    const BYTE call[]={0xff,0xd0,0xba};
    const BYTE capture[]={0x0f,0xae,0x02,0xba};
    const BYTE restore[]={0x0f,0xae,0x0a,0xba};
    const BYTE end[]={0x0f,0xae,0x02,0xc3};
#endif
    memset(code,0x90,sizeof(code));
    memcpy(code+n,begin,sizeof(begin));n+=(UINT)sizeof(begin);memcpy(code+n,&state,sizeof(state));n+=(UINT)sizeof(state);
    memcpy(code+n,save,sizeof(save));n+=(UINT)sizeof(save);memcpy(code+n,&function,sizeof(function));n+=(UINT)sizeof(function);
    memcpy(code+n,call,sizeof(call));n+=(UINT)sizeof(call);memcpy(code+n,&postAddress,sizeof(postAddress));n+=(UINT)sizeof(postAddress);
    memcpy(code+n,capture,sizeof(capture));n+=(UINT)sizeof(capture);memcpy(code+n,&state,sizeof(state));n+=(UINT)sizeof(state);
    memcpy(code+n,restore,sizeof(restore));n+=(UINT)sizeof(restore);memcpy(code+n,&restoredAddress,sizeof(restoredAddress));n+=(UINT)sizeof(restoredAddress);
    memcpy(code+n,end,sizeof(end));n+=(UINT)sizeof(end);
    require(n<=sizeof(code),"bounded FP-preserving fixture wrapper");
    memcpy(area+1024,code,sizeof(code));
    require(FlushInstructionCache(GetCurrentProcess(),area+1024,sizeof(code)),"flush FP-preserving fixture wrapper");
    ((FUNCTION)(area+1024))(output);
    require(post[4]==0,"owned source/original/detour leaves the x87 stack balanced and empty");
    require(!memcmp(restored,backup,5)&&!memcmp(restored+24,backup+24,4),
        "wrapper restores caller x87 control/status/tags and MXCSR");
#if defined(_M_X64) || defined(__x86_64__)
    require(!memcmp(restored+160,backup+160,256),"wrapper restores all sixteen caller XMM registers");
#else
    require(!memcmp(restored+160,backup+160,128),"wrapper restores all eight caller XMM registers");
#endif
}

static uint64_t saved_ip(const BYTE *output,UINT offset,UINT width)
{uint64_t ip=0;memcpy(&ip,output+offset,width);return ip;}
static void check_source_ip(const BYTE *output,UINT offset,UINT width,BOOL fxsave,BYTE *producer)
{
    uint64_t ip=saved_ip(output,offset,width);
    uint64_t expected=width==8?(uint64_t)(ULONG_PTR)producer:(uint32_t)(ULONG_PTR)producer;
    /* AMD CPUs can zero FXSAVE's exception pointers for a clear exception
     * summary. FNSTENV/FNSAVE provide the decisive exact-FIP observation. */
    require(ip==expected||(fxsave&&ip==0),"source save records its exact producer IP or architectural FXSAVE zero");
}
static void check_canary(const BYTE *output)
{
    BYTE expected[16];memset(expected,0xa5,sizeof(expected));
    require(!memcmp(output+512,expected,sizeof(expected)),"state save stays within the aligned caller buffer");
}
static void refuse(BYTE *source,BYTE *detour)
{
    BYTE snapshot[128];LPVOID original=(LPVOID)(ULONG_PTR)0x1234;
    memcpy(snapshot,source,sizeof(snapshot));
    require(MTH_CreateHook(source,detour,&original)==MTH_ERROR_UNSUPPORTED_FUNCTION,
        "x87 producer refuses before original publication");
    require(original==(LPVOID)(ULONG_PTR)0x1234&&!memcmp(snapshot,source,sizeof(snapshot)),
        "x87 refusal preserves original output and all source bytes");
    require(MTH_EnableHook(source)==MTH_ERROR_NOT_CREATED&&MTH_RemoveHook(source)==MTH_ERROR_NOT_CREATED,
        "x87 refusal leaves no hook owner to enable or retire");
}

int main(void)
{
    static const struct {BYTE code[16];UINT length,offset,width;BOOL fxsave;} cases[]={
        {{0xd9,0xee,0xd9,0x31,0xdd,0xd8,0xc3},7,12,4,FALSE},
        {{0xd9,0xee,0x9b,0xd9,0x31,0xdd,0xd8,0xc3},8,12,4,FALSE},
        {{0xd9,0xee,0xdd,0x31,0xc3},5,12,4,FALSE},
        {{0xd9,0xee,0x9b,0xdd,0x31,0xc3},6,12,4,FALSE},
        {{0xd9,0xee,0x0f,0xae,1,0xdd,0xd8,0xc3},8,8,4,TRUE},
#if defined(_M_X64) || defined(__x86_64__)
        {{0xd9,0xee,0x48,0x0f,0xae,1,0xdd,0xd8,0xc3},9,8,8,TRUE},
#endif
        {{0xd9,0xee,0x90,0x90,0x90,0xd9,0x31,0xdd,0xd8,0xc3},10,12,4,FALSE},
        {{0xd9,0xee,0x90,0x90,0x90,0x0f,0xae,1,0xdd,0xd8,0xc3},11,8,4,TRUE},
        {{0xd9,0xee,0x90,0x90,0x90,0xdd,0x31,0xc3},8,12,4,FALSE}
    };
    const BYTE extra[][3]={{0x0f,0xae,0x21},{0x0f,0xae,0x29},{0x0f,0xae,0x31},
        {0x0f,0xc7,0x19},{0x0f,0xc7,0x21},{0x0f,0xc7,0x29}};
    _Alignas(16) BYTE output[528],backup[512];
    BYTE *area,*source,*detour;DWORD before,after;UINT test,op;
#if defined(_M_X64) || defined(__x86_64__)
    RUNTIME_FUNCTION functions[]={{256,512,2048},{1024,1152,2056}};DWORD64 base;
    const BYTE info[]={1,0,0,0,0,0,0,0,1,4,1,0,4,0x42,0,0};
#endif
    require(GetProcessHandleCount(GetCurrentProcess(),&before),"capture x87 handle baseline");
    area=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    require(area!=NULL,"allocate owned x87 fixture");source=area+256;detour=area+768;
    memset(area,0x90,4096);detour[0]=0xc7;detour[1]=1;detour[2]=9;memset(detour+3,0,3);detour[6]=0xc3;
#if defined(_M_X64) || defined(__x86_64__)
    memcpy(area+2048,info,sizeof(info));
    require(RtlAddFunctionTable(functions,2,(DWORD64)(ULONG_PTR)area),"register leaf source and ABI-valid wrapper tables");
#endif
    require(MTH_Initialize()==MTH_OK,"initialize x87 fixture engine");
    for(test=0;test<sizeof(cases)/sizeof(cases[0]);++test)
    {
        memset(source,0x90,128);memcpy(source,cases[test].code,cases[test].length);
        require(FlushInstructionCache(GetCurrentProcess(),area,4096),"flush x87 report source");
        memset(output,0xa5,sizeof(output));invoke(area,source,output,backup);
        check_source_ip(output,cases[test].offset,cases[test].width,cases[test].fxsave,source);check_canary(output);
        /* Exact report is first; the guard-removal control must fail here,
         * before an unsafe original is ever executed or enabled. */
        refuse(source,detour);
    }
    for(test=0;test<sizeof(extra)/sizeof(extra[0]);++test)
    {memset(source,0x90,128);memcpy(source,extra[test],3);source[3]=0xc3;refuse(source,detour);}
    /* The same x87/state-save bodies after five ordinary NOPs stay at their
     * actual source IP. Execute both paths throughout the complete lifecycle. */
    for(test=0;test<sizeof(cases)/sizeof(cases[0]);++test)
    {
        BYTE snapshot[128];LPVOID original=NULL;uint64_t expected;
        memset(source,0x90,128);memcpy(source+5,cases[test].code,cases[test].length);memcpy(snapshot,source,sizeof(snapshot));
        require(FlushInstructionCache(GetCurrentProcess(),area,4096),"flush unrelocated x87 body control");
        memset(output,0xa5,sizeof(output));invoke(area,source,output,backup);
        check_source_ip(output,cases[test].offset,cases[test].width,cases[test].fxsave,source+5);
        expected=saved_ip(output,cases[test].offset,cases[test].width);check_canary(output);
        require(MTH_CreateHook(source,detour,&original)==MTH_OK&&original!=NULL,"publish ordinary prefix before an unrelocated x87 body");
        memset(output,0xa5,sizeof(output));invoke(area,original,output,backup);
        require(saved_ip(output,cases[test].offset,cases[test].width)==expected&&!memcmp(source,snapshot,sizeof(snapshot)),
            "original observes the unchanged source FIP before enable");check_canary(output);
#if defined(_M_X64) || defined(__x86_64__)
        require(RtlLookupFunctionEntry((DWORD64)(ULONG_PTR)original,&base,NULL)==NULL,
            "ordinary NOP prefix correctly retains leaf unwind fallback");
#endif
        require(MTH_EnableHook(source)==MTH_OK,"enable ordinary prefix before x87 body");
        memset(output,0xa5,sizeof(output));invoke(area,source,output,backup);
        require(output[0]==9&&output[1]==0&&output[2]==0&&output[3]==0,"enabled target executes the owned detour");check_canary(output);
        memset(output,0xa5,sizeof(output));invoke(area,original,output,backup);
        require(saved_ip(output,cases[test].offset,cases[test].width)==expected,"enabled original keeps source FIP");check_canary(output);
        require(MTH_DisableHook(source)==MTH_OK&&!memcmp(source,snapshot,sizeof(snapshot)),"restore every x87 source byte");
        require(MTH_RemoveHook(source)==MTH_OK,"retire leaf original before source storage");
        memset(output,0xa5,sizeof(output));invoke(area,source,output,backup);
        require(saved_ip(output,cases[test].offset,cases[test].width)==expected,"retired source keeps its independently observed FIP");check_canary(output);
    }
    /* FXSAVE/FXRSTOR themselves do not acquire a new x87 FIP. A fixed-size
     * copied save remains supported; the wrapper seeds identical prior state. */
    for(op=0;op<2;++op)
    {
        BYTE snapshot[128];LPVOID original=NULL;uint64_t expected;
        memset(source,0x90,128);source[0]=0x0f;source[1]=0xae;source[2]=1;source[3]=0xc3;
        require(FlushInstructionCache(GetCurrentProcess(),area,4096),"flush fixed FXSAVE source");
        memset(output,0xa5,sizeof(output));invoke(area,source,output,backup);expected=saved_ip(output,8,4);
        if(op){source[2]=9;require(FlushInstructionCache(GetCurrentProcess(),area,4096),"flush fixed FXRSTOR source");}
        memcpy(snapshot,source,sizeof(snapshot));
        require(MTH_CreateHook(source,detour,&original)==MTH_OK&&original!=NULL,"fixed FX state operation without copied producer remains supported");
        invoke(area,original,output,backup);
        require(saved_ip(output,8,4)==expected,"fixed FX operation preserves the prior observed FIP");check_canary(output);
        require(MTH_EnableHook(source)==MTH_OK,"enable fixed FX state operation");
        invoke(area,original,output,backup);
        require(saved_ip(output,8,4)==expected,"enabled fixed FX original preserves prior FIP");check_canary(output);
        require(MTH_DisableHook(source)==MTH_OK&&!memcmp(source,snapshot,sizeof(snapshot)),"restore fixed FX source bytes");
        require(MTH_RemoveHook(source)==MTH_OK,"retire fixed FX original");
    }
    require(MTH_Uninitialize()==MTH_OK,"complete x87 engine cleanup");
#if defined(_M_X64) || defined(__x86_64__)
    require(RtlLookupFunctionEntry((DWORD64)(ULONG_PTR)source,&base,NULL)!=NULL,"source metadata remains owned after engine shutdown");
    require(RtlDeleteFunctionTable(functions),"delete source/wrapper metadata after all originals retire");
    require(RtlLookupFunctionEntry((DWORD64)(ULONG_PTR)source,&base,NULL)==NULL,"all fixture runtime tables are retired");
#endif
    require(VirtualFree(area,0,MEM_RELEASE),"release x87 fixture storage last");
    require(GetProcessHandleCount(GetCurrentProcess(),&after)&&after==before,"restore x87 handle baseline");
    printf("PASS: %u native x87 FIP/refusal/state-save/restore/lifecycle checks\n",checks);return 0;
}
