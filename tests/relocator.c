// SPDX-License-Identifier: GPL-3.0-only
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "trampoline.h"

static unsigned checks;
static void check(BOOL condition, const char *description)
{
    ++checks;
    if (!condition) { fprintf(stderr, "FAIL: %s\n", description); exit(1); }
}

int main(void)
{
    SYSTEM_INFO info;
    BYTE *code;
    TRAMPOLINE ct;
    INT32 displacement, relocated;
    DWORD old;
    const BYTE vex[] = {0xc4,0xe2,0x6d,0x8c,0x08,0xc3};
    const BYTE xbegin[] = {0xc7,0xf8,0,1,0,0,0xc3};
    GetSystemInfo(&info);
    code = VirtualAlloc(NULL, info.dwPageSize*2, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    check(code != NULL, "allocate relocator fixture");
    memset(code, 0x90, info.dwPageSize*2);
    memset(&ct, 0, sizeof ct);
    ct.pTarget=code+512; ct.pTrampoline=code+64; ct.pDetour=code+1024;
    code[512]=0x48; code[513]=0x8b; code[514]=5;
    displacement=INT32_MAX; memcpy(code+515,&displacement,4); code[519]=0xc3;
    check(!MthInternal_CreateTrampolineFunction(&ct), "reject positive signed displacement overflow");
    ct.pTarget=code+64; ct.pTrampoline=code+512;
    code[64]=0x48; code[65]=0x8b; code[66]=5;
    displacement=INT32_MIN; memcpy(code+67,&displacement,4); code[71]=0xc3;
    check(!MthInternal_CreateTrampolineFunction(&ct), "reject negative signed displacement overflow");
    displacement=128; memcpy(code+67,&displacement,4);
    check(MthInternal_CreateTrampolineFunction(&ct), "accept representable displacement");
    memcpy(&relocated,code+515,4);
    check((INT64)(code+519)+relocated==(INT64)(code+71)+displacement,
        "retain the exact RIP-relative effective address");
    memcpy(code+64,vex,sizeof vex);
    check(MthInternal_CreateTrampolineFunction(&ct), "accept VPMASKMOVD memory load");
    check(!memcmp(code+512,vex,5), "preserve VEX instruction instead of emitting Jcc");
    memcpy(code+64,xbegin,sizeof xbegin);
    check(!MthInternal_CreateTrampolineFunction(&ct), "refuse unhandled relative XBEGIN");
    memset(code,0x90,info.dwPageSize);
    code[info.dwPageSize-1]=0xc3;
    check(VirtualProtect(code+info.dwPageSize,info.dwPageSize,PAGE_NOACCESS,&old),
        "protect inaccessible trailing page");
    ct.pTarget=code+info.dwPageSize-1; ct.pTrampoline=code+64;
    check(!MthInternal_CreateTrampolineFunction(&ct), "reject inaccessible padding without a process fault");
    check(VirtualFree(code,0,MEM_RELEASE), "release relocator fixture");
    printf("PASS: %u MithrilHook relocation checks\n",checks);
    return 0;
}
