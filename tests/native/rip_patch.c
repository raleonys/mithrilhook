// SPDX-License-Identifier: GPL-3.0-only
#include <windows.h>
#include <MithrilHook.h>
#include <stdio.h>
#include <string.h>

typedef ULONG_PTR (__cdecl *FUNCTION)(void);
static unsigned checks;
static void require(BOOL ok, const char *why)
{ ++checks; if (!ok) { fprintf(stderr,"FAIL: %s\n",why); ExitProcess(1); } }

int main(void)
{
    static const struct { BYTE bytes[16]; UINT length; INT dataOffset; UINT dataWidth; ULONG_PTR result; } good[] = {
        {{0x8b,5,1,0,0,0,0xc3,42,0,0,0},11,0,0,42},
        {{0x48,0x8d,5,0xf9,0xff,0xff,0xff,0xc3},8,0,0,0},
        {{0x8b,5,0xf6,0xff,0xff,0xff,0xc3},7,-4,4,42},
        {{0x0f,0xb6,5,0xf8,0xff,0xff,0xff,0xc3},8,-1,1,42},
        {{0x0f,0xb6,5,0xfe,0xff,0xff,0xff,0xc3},8,0,0,255},
        {{0x64,0x48,0x8d,5,0xf8,0xff,0xff,0xff,0xc3},9,0,0,0},
        {{0x65,0x48,0x8d,5,0xf8,0xff,0xff,0xff,0xc3},9,0,0,0},
        {{0x0f,0xae,5,0xf9,0xfd,0xff,0xff,0xb8,42,0,0,0,0xc3},13,0,0,42}
    };
    static const struct { BYTE bytes[16]; UINT length; } bad[] = {
        {{0x8b,5,0xfa,0xff,0xff,0xff,0xc3},7},
        {{0x89,5,0xfa,0xff,0xff,0xff,0xc3},7},
        {{0x66,0x8b,5,0xf8,0xff,0xff,0xff,0xc3},8},
        {{0x8b,5,0xf7,0xff,0xff,0xff,0xc3},7},
        {{0x48,0x0f,0xa3,0x0d,56,0,0,0,0xc3},9},
        {{0x48,0x0f,0xab,0x0d,56,0,0,0,0xc3},9},
        {{0x48,0x0f,0xb3,0x0d,56,0,0,0,0xc3},9},
        {{0x48,0x0f,0xbb,0x0d,56,0,0,0,0xc3},9},
        {{0x0f,0xae,5,0x79,0xff,0xff,0xff,0xc3},8},
        {{0x0f,0xae,0x0d,0x79,0xff,0xff,0xff,0xc3},8},
        {{0x0f,0xae,0x25,57,0,0,0,0xc3},8},
        {{0x64,0x8b,5,57,0,0,0,0xc3},8},
        {{0x65,0x8b,5,57,0,0,0,0xc3},8},
        {{0xc5,0xf9,0x6f,5,56,0,0,0,0xc3},9},
        {{0x8f,0xe9,0x78,0x92,5,55,0,0,0,0xc3},10}
    };
    BYTE *area, *source, *detour;
    DWORD before, after;
    UINT index;
    require(GetProcessHandleCount(GetCurrentProcess(),&before),"capture RIP fixture handle baseline");
    area=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    require(area!=NULL,"allocate owned RIP fixture"); source=area+1024;detour=area+2048;
    memset(area,0x90,4096);detour[0]=0xb8;detour[1]=9;memset(detour+2,0,3);detour[5]=0xc3;
    require(MTH_Initialize()==MTH_OK,"initialize RIP fixture engine");
    for(index=0;index<sizeof(good)/sizeof(good[0]);++index)
    {
        BYTE snapshot[64];LPVOID original=NULL;ULONG_PTR expected=good[index].result;
        memset(source,0x90,64);memcpy(source,good[index].bytes,good[index].length);
        if(good[index].dataWidth){DWORD value=42;memcpy(source+good[index].dataOffset,&value,good[index].dataWidth);}
        if(expected==0)expected=(ULONG_PTR)source; /* LEA preserves the original address. */
        memcpy(snapshot,source,sizeof(snapshot));
        require(FlushInstructionCache(GetCurrentProcess(),area,4096),"flush source and detour");
        require(((FUNCTION)source)()==expected,"source independently returns expected RIP value/address");
        require(MTH_CreateHook(source,detour,&original)==MTH_OK&&original!=NULL,"publish proven nonoverlapping RIP operand");
        require(!memcmp(source,snapshot,sizeof(snapshot))&&((FUNCTION)original)()==expected,"creation preserves bytes and original result");
        require(MTH_EnableHook(source)==MTH_OK&&((FUNCTION)source)()==9&&((FUNCTION)original)()==expected,"enabled hook retains original RIP value/address");
        require(MTH_DisableHook(source)==MTH_OK&&!memcmp(source,snapshot,sizeof(snapshot)),"disable restores RIP source bytes");
        require(MTH_RemoveHook(source)==MTH_OK&&((FUNCTION)source)()==expected,"retire RIP owner and preserve source behavior");
    }
    /* Unknown ISA/segment/indexed forms and self-writing operands are never
     * executed. Refusal must leave no published original or changed bytes. */
    for(index=0;index<sizeof(bad)/sizeof(bad[0]);++index)
    {
        BYTE snapshot[64];LPVOID original=(LPVOID)(ULONG_PTR)0x1234;
        memset(source,0x90,64);memcpy(source,bad[index].bytes,bad[index].length);memcpy(snapshot,source,sizeof(snapshot));
        require(MTH_CreateHook(source,detour,&original)==MTH_ERROR_UNSUPPORTED_FUNCTION,"refuse overlapping or unproven RIP access");
        require(original==(LPVOID)(ULONG_PTR)0x1234&&!memcmp(source,snapshot,sizeof(snapshot)),"RIP refusal preserves output and source bytes");
    }
    require(MTH_Uninitialize()==MTH_OK,"finish RIP fixture engine cleanup");
    require(VirtualFree(area,0,MEM_RELEASE),"release RIP fixture storage last");
    require(GetProcessHandleCount(GetCurrentProcess(),&after)&&after==before,"restore RIP fixture handle baseline");
    printf("PASS: %u native RIP access execution/refusal/publication/cleanup checks\n",checks);return 0;
}
