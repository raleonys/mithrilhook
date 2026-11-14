// SPDX-License-Identifier: GPL-3.0-only
#include <windows.h>
#include <MithrilHook.h>
#include <stdio.h>
#include <string.h>

static unsigned checks;
static void require(BOOL ok,const char *why)
{++checks;if(!ok){fprintf(stderr,"FAIL: %s\n",why);ExitProcess(1);}}

static void refuse(BYTE *source,BYTE *detour)
{
    BYTE snapshot[64];LPVOID original=(LPVOID)(ULONG_PTR)0x1234;
    memcpy(snapshot,source,sizeof(snapshot));
    require(MTH_CreateHook(source,detour,&original)==MTH_ERROR_UNSUPPORTED_FUNCTION,
        "transition instruction refuses before original publication");
    require(original==(LPVOID)(ULONG_PTR)0x1234&&!memcmp(source,snapshot,sizeof(snapshot)),
        "transition refusal preserves original output and source bytes");
    require(MTH_EnableHook(source)==MTH_ERROR_NOT_CREATED&&MTH_RemoveHook(source)==MTH_ERROR_NOT_CREATED,
        "transition refusal leaves no hook owner to enable or retire");
}

#if defined(_M_X64) || defined(__x86_64__)
static DWORD yield_service(void)
{
    BYTE stub[32];SIZE_T copied;DWORD service;UINT offset=0,index;BOOL found=FALSE;
    const BYTE endbr[]={0xf3,0x0f,0x1e,0xfa},prefix[]={0x4c,0x8b,0xd1,0xb8};
    FARPROC target=GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtYieldExecution");
    require(target!=NULL,"resolve loaded no-argument NtYieldExecution");
    require(ReadProcessMemory(GetCurrentProcess(),(LPCVOID)(ULONG_PTR)target,stub,sizeof(stub),&copied)&&copied==sizeof(stub),
        "read bounded NtYieldExecution service stub");
    if(!memcmp(stub,endbr,sizeof(endbr)))offset=4;
    require(!memcmp(stub+offset,prefix,sizeof(prefix)),"NtYieldExecution has the expected bounded service-number prefix");
    memcpy(&service,stub+offset+4,sizeof(service));
    for(index=offset+8;index+1<sizeof(stub);++index)
        if(stub[index]==0x0f&&stub[index+1]==5)found=TRUE;
    require(found&&service<=0xffff,"loaded NtYieldExecution contains a syscall gate and bounded service identifier");
    return service;
}

static LONG invoke(BYTE *area,LPVOID entry,DWORD service)
{
    typedef LONG (__cdecl *WRAPPER)(void);
    const BYTE prefix[]={0x48,0x83,0xec,0x28,0xb8};
    const BYTE address[]={0x48,0xba};
    const BYTE suffix[]={0xff,0xd2,0x48,0x83,0xc4,0x28,0xc3};
    ULONG_PTR pointer=(ULONG_PTR)entry;BYTE code[64];UINT n=0;
    memset(code,0x90,sizeof(code));memcpy(code+n,prefix,sizeof(prefix));n+=(UINT)sizeof(prefix);
    memcpy(code+n,&service,sizeof(service));n+=(UINT)sizeof(service);
    memcpy(code+n,address,sizeof(address));n+=(UINT)sizeof(address);memcpy(code+n,&pointer,sizeof(pointer));n+=(UINT)sizeof(pointer);
    memcpy(code+n,suffix,sizeof(suffix));
    memcpy(area+1024,code,sizeof(code));
    require(FlushInstructionCache(GetCurrentProcess(),area+1024,sizeof(code)),"flush balanced no-argument service wrapper");
    return ((WRAPPER)(area+1024))();
}

static void build_syscall(BYTE *area,UINT site)
{
    BYTE *source=area+256,*capture=area+2048;
    INT32 displacement=(INT32)(capture-(source+site+9));
    memset(source,0x90,64);source[site]=0x0f;source[site+1]=5;
    source[site+2]=0x48;source[site+3]=0x89;source[site+4]=0x0d;
    memcpy(source+site+5,&displacement,4);source[site+9]=0xc3;
    require(FlushInstructionCache(GetCurrentProcess(),source,64),"flush owned syscall and source-resident RCX store");
}

static void observe(BYTE *area,LPVOID entry,DWORD service,BYTE *expected)
{
    DWORD64 *capture=(DWORD64*)(area+2048);LONG status;*capture=0;
    status=invoke(area,entry,service);
    require(status==0||status==(LONG)0x40000024,"bounded NtYieldExecution completes with its documented status");
    require(*capture==(DWORD64)(ULONG_PTR)expected,"genuine Windows SYSCALL exposes the exact source continuation in RCX");
}
#endif

int main(void)
{
    const struct {BYTE bytes[8];UINT size;} gates[]={
        {{0x0f,0x05},2},{{0x0f,0x07},2},{{0x0f,0x34},2},{{0x0f,0x35},2},{{0x0f,0xaa},2},
        {{0xcc},1},{{0xcd,0x2e},2},{{0xce},1},{{0xcf},1},{{0xf1},1},
        {{0xcb},1},{{0xca,0,0},3},{{0x9a,0,0,0,0,0,0},7},{{0xea,0,0,0,0,0,0},7},
        {{0xff,0x19},2},{{0xff,0x29},2}
    };
    const BYTE prefixes[]={0,0x66,0x67,0x2e};
    BYTE *area,*source,*detour;DWORD before,after;UINT kind,prefix,site;
#if defined(_M_X64) || defined(__x86_64__)
    DWORD service=yield_service();DWORD64 base;
    RUNTIME_FUNCTION functions[]={{256,320,3072},{1024,1088,3080}};
    const BYTE info[]={1,0,0,0,0,0,0,0,1,4,1,0,4,0x42,0,0};
#endif
    require(GetProcessHandleCount(GetCurrentProcess(),&before),"capture transition handle baseline");
    area=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    require(area!=NULL,"allocate owned transition fixture");source=area+256;detour=area+512;
    memset(area,0x90,4096);detour[0]=0xb8;detour[1]=9;memset(detour+2,0,3);detour[5]=0xc3;
#if defined(_M_X64) || defined(__x86_64__)
    memcpy(area+3072,info,sizeof(info));
    require(RtlAddFunctionTable(functions,2,(DWORD64)(ULONG_PTR)area),"register source and ABI-valid wrapper runtime tables");
#endif
    require(MTH_Initialize()==MTH_OK,"initialize transition fixture engine");
#if defined(_M_X64) || defined(__x86_64__)
    build_syscall(area,3);observe(area,source,service,source+5);
    /* The exact five-byte-prefix reproducer is the negative control's first
     * refusal oracle, before any unsafe original can execute or be enabled. */
    refuse(source,detour);
    for(site=0;site<5;++site)
    {
        if(site==3)continue;
        build_syscall(area,site);observe(area,source,service,source+site+2);refuse(source,detour);
    }
#else
    /* Do not run a native x86 system-service ABI guessed from the x64 case.
     * SYSENTER is decoded here only, giving the exact guard-removal oracle. */
    memset(source,0x90,64);source[3]=0x0f;source[4]=0x34;source[5]=0xc3;refuse(source,detour);
#endif
    /* Privileged returns, traps, interrupt gates and far transitions are
     * structural refusal cases only; none is executed. */
    for(kind=0;kind<sizeof(gates)/sizeof(gates[0]);++kind)
    for(prefix=0;prefix<sizeof(prefixes);++prefix)
    for(site=0;site<5;++site)
    {
        UINT size=prefix?1:0;memset(source,0x90,64);
        if(size)source[site]=prefixes[prefix];
        memcpy(source+site+size,gates[kind].bytes,gates[kind].size);source[site+size+gates[kind].size]=0xc3;
        refuse(source,detour);
    }
#if defined(_M_X64) || defined(__x86_64__)
    for(site=5;site<10;++site)
    {
        BYTE snapshot[64];LPVOID original=NULL;DWORD64 *capture=(DWORD64*)(area+2048);
        build_syscall(area,site);observe(area,source,service,source+site+2);memcpy(snapshot,source,sizeof(snapshot));
        require(MTH_CreateHook(source,detour,&original)==MTH_OK&&original!=NULL,"publish ordinary prefix with a source-resident syscall body");
        observe(area,original,service,source+site+2);
        require(!memcmp(source,snapshot,sizeof(snapshot)),"creation preserves the source-resident syscall body");
        require(RtlLookupFunctionEntry((DWORD64)(ULONG_PTR)original,&base,NULL)==NULL,"neutral copied prefix correctly uses leaf unwind fallback");
        require(MTH_EnableHook(source)==MTH_OK,"enable syscall-body positive control");
        *capture=0;require(invoke(area,source,service)==9&&*capture==0,"enabled detour bypasses the service without writing its capture");
        observe(area,original,service,source+site+2);
        require(MTH_DisableHook(source)==MTH_OK&&!memcmp(source,snapshot,sizeof(snapshot)),"disable restores all syscall-source bytes");
        observe(area,source,service,source+site+2);
        require(MTH_RemoveHook(source)==MTH_OK,"retire syscall-body original owner");
        observe(area,source,service,source+site+2);
    }
#endif
    {
        typedef int (__cdecl *LEAF)(void);BYTE snapshot[64];LPVOID original=NULL;
        memset(source,0x90,64);source[0]=0xb8;source[1]=42;memset(source+2,0,3);source[5]=0xc3;
        memcpy(snapshot,source,sizeof(snapshot));
        require(FlushInstructionCache(GetCurrentProcess(),area,4096),"flush ordinary near-return control");
        require(((LEAF)source)()==42,"ordinary leaf source executes independently");
        require(MTH_CreateHook(source,detour,&original)==MTH_OK&&((LEAF)original)()==42,"ordinary leaf remains creatable after transition refusals");
        require(MTH_EnableHook(source)==MTH_OK&&((LEAF)source)()==9&&((LEAF)original)()==42,"ordinary leaf target/original remain correct while enabled");
        require(MTH_DisableHook(source)==MTH_OK&&!memcmp(source,snapshot,sizeof(snapshot)),"ordinary leaf source bytes restore");
        require(MTH_RemoveHook(source)==MTH_OK&&((LEAF)source)()==42,"ordinary near-return control retires correctly");
    }
    require(MTH_Uninitialize()==MTH_OK,"complete transition engine cleanup");
#if defined(_M_X64) || defined(__x86_64__)
    require(RtlLookupFunctionEntry((DWORD64)(ULONG_PTR)source,&base,NULL)!=NULL,"source metadata survives engine shutdown");
    require(RtlDeleteFunctionTable(functions),"retire source/wrapper metadata after every original");
    require(RtlLookupFunctionEntry((DWORD64)(ULONG_PTR)source,&base,NULL)==NULL,"fixture runtime-table retirement completes");
#endif
    require(VirtualFree(area,0,MEM_RELEASE),"release transition storage last");
    require(GetProcessHandleCount(GetCurrentProcess(),&after)&&after==before,"restore transition handle baseline");
    printf("PASS: %u native transition/syscall/refusal/restoration/retirement checks\n",checks);return 0;
}
