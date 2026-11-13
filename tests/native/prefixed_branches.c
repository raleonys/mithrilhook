// SPDX-License-Identifier: GPL-3.0-only
// Refusal is checked without executing vendor-dependent 66 near-branch bytes.
#include <windows.h>
#include <MithrilHook.h>
#include <stdio.h>
#include <string.h>
static unsigned checks;
static void require(BOOL ok,const char *why)
{++checks;if(!ok){fprintf(stderr,"FAIL: %s\n",why);ExitProcess(1);}}
int main(void)
{
    static const BYTE prefixes[][5]={{0x66},{0x66,0x66},{0x2e,0x66},{0xf2,0x66},{0xf3,0x66},{0x67,0x66},{0x66,0x48},{0x64,0x66}};
    static const BYTE lengths[]={1,2,2,2,2,2,2,2};
    BYTE *code;DWORD before,after;UINT prefix,kind,sign;
    typedef int (__cdecl *FUNCTION)(void);
    require(GetProcessHandleCount(GetCurrentProcess(),&before),"capture prefix-fixture handle baseline");
    code=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    require(code!=NULL,"allocate owned branch fixture");memset(code,0x90,4096);
    code[64]=0xb8;code[65]=9;code[66]=code[67]=code[68]=0;code[69]=0xc3;
    require(MTH_Initialize()==MTH_OK,"initialize prefix refusal engine");
    for(prefix=0;prefix<sizeof(lengths);++prefix)
    for(kind=0;kind<18;++kind)
    for(sign=0;sign<2;++sign)
    {
        BYTE snapshot[32];LPVOID original=(LPVOID)(ULONG_PTR)0x1234;UINT n=lengths[prefix];
#if defined(_M_IX86) || defined(__i386__)
        if(prefix==6)continue; /* 48 is DEC EAX, not REX, in 32-bit mode. */
#endif
        memset(code,0x90,32);memcpy(code,prefixes[prefix],n);
        if(kind<2)code[n++]=kind?0xe9:0xe8;
        else {code[n++]=0x0f;code[n++]=(BYTE)(0x80+kind-2);}
        code[n++]=sign?0xfb:5;code[n++]=sign?0xff:0;code[n++]=sign?0xff:0;code[n++]=sign?0xff:0;
        memcpy(snapshot,code,sizeof(snapshot));
        require(FlushInstructionCache(GetCurrentProcess(),code,32),"flush prefix input");
        require(MTH_CreateHook(code,code+64,&original)==MTH_ERROR_UNSUPPORTED_FUNCTION,
            "refuse ambiguous prefixed near CALL/JMP/all Jcc forms");
        require(original==(LPVOID)(ULONG_PTR)0x1234&&!memcmp(snapshot,code,sizeof(snapshot)),
            "refused prefix preserves caller output and every target byte");
    }
    /* An instruction beyond the relocated prefix is not rewritten. Its own
     * vendor-specific semantics remain at the original address. */
    memset(code,0x90,32);code[5]=0x66;code[6]=0xe9;code[7]=5;code[8]=code[9]=code[10]=0;
    {LPVOID original=NULL;
     require(MTH_CreateHook(code,code+64,&original)==MTH_OK&&original!=NULL,
        "an unrelocated prefixed instruction does not cause a compatibility refusal");
     require(MTH_RemoveHook(code)==MTH_OK,"retire noncopied-prefix positive control");}
    /* Same displacement with an ordinary JMP retains its destination/result. */
    memset(code,0x90,32);code[0]=0xe9;{INT32 delta=11;memcpy(code+1,&delta,4);}
    code[16]=0xb8;code[17]=42;code[18]=code[19]=code[20]=0;code[21]=0xc3;
    require(FlushInstructionCache(GetCurrentProcess(),code,32),"flush unprefixed control");
    {LPVOID original=NULL;
     require(((FUNCTION)code)()==42,"owned unprefixed source reaches expected destination");
     require(MTH_CreateHook(code,code+64,&original)==MTH_OK&&original!=NULL,"ordinary near branch remains supported");
     require(((FUNCTION)original)()==42,"ordinary trampoline preserves exact branch result");
     require(MTH_EnableHook(code)==MTH_OK&&((FUNCTION)code)()==9&&((FUNCTION)original)()==42,"owned enabled branch preserves detour and original behavior");
     require(MTH_DisableHook(code)==MTH_OK&&((FUNCTION)code)()==42,"restore unprefixed target result");
     require(MTH_RemoveHook(code)==MTH_OK,"retire unprefixed control owner");}
    require(MTH_Uninitialize()==MTH_OK,"complete all prefix cleanup owners");
    require(VirtualFree(code,0,MEM_RELEASE),"release branch fixture last");
    require(GetProcessHandleCount(GetCurrentProcess(),&after)&&after==before,"restore prefix-fixture handle baseline");
    printf("PASS: %u native prefixed-branch refusal/publication and ordinary-result checks\n",checks);
    return 0;
}
