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

static void byte_alias_cases(BYTE *code)
{
    const BYTE nonRex[]={0,1,2,3,0,1,2,3};
    const UINT frames[]={0,3,5,6,7,12,13,14,15};
    /* Immediate, r/m destination and reg destination families, plus SETcc.
     * Group selectors remain raw opcode extensions, never normalized registers. */
    const BYTE forms[][4]={
        {0xb0,0,0x12,0}, {0xc6,0,0x12,0}, {0x88,0,0,0},
        {0x86,0,0,0}, {0x00,0,0,0}, {0x80,0,1,0},
        {0xfe,0,0,0}, {0xf6,2,0,0}, {0xc0,4,1,0},
        {0xd0,4,0,0}, {0xd2,4,0,0}, {0x0f,0x95,0,0},
        {0x8a,0,0,1}, {0x02,0,0,1}
    };
    UINT prefix,encoded,frame,form;
    for(prefix=0;prefix<3;++prefix)
    for(encoded=0;encoded<8;++encoded)
    for(frame=0;frame<sizeof(frames)/sizeof(frames[0]);++frame)
    for(form=0;form<sizeof(forms)/sizeof(forms[0]);++form)
    {
        UINT n=0,reg=prefix==0?nonRex[encoded]:prefix==1?encoded:encoded+8;
        BOOL expected=reg!=4 && (frames[frame]==0 || reg!=frames[frame]);
        BOOL destinationReg=forms[form][3]!=0;
        if(prefix)code[n++]=(BYTE)(prefix==1?0x40:destinationReg?0x44:0x41);
        if(forms[form][0]==0xb0){code[n++]=(BYTE)(0xb0+encoded);code[n++]=0x12;}
        else if(forms[form][0]==0x0f){code[n++]=0x0f;code[n++]=0x95;code[n++]=(BYTE)(0xc0+encoded);}
        else
        {
            code[n++]=forms[form][0];
            code[n++]=(BYTE)(0xc0+(destinationReg?encoded*8:forms[form][1]*8+encoded));
            if(forms[form][0]==0xc6 || forms[form][0]==0x80 || forms[form][0]==0xc0)code[n++]=forms[form][2];
        }
        check(MthInternal_IsUnwindNeutralInstruction(code,n,frames[frame])==expected,
            "byte destination aliases respect RSP/frame ownership with and without REX");
    }
    { const BYTE word[]={0x66,0xbd,0x12,0x34};
      memcpy(code,word,sizeof(word));
      check(!MthInternal_IsUnwindNeutralInstruction(code,sizeof(word),5),"word BP write remains protected"); }
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
    check(ct.oldSize==7, "relocated source span excludes the jump-back sentinel instruction");
    memcpy(&relocated,code+515,4);
    check((INT64)(code+519)+relocated==(INT64)(code+71)+displacement,
        "retain the exact RIP-relative effective address");
    memcpy(code+64,vex,sizeof vex);
    check(MthInternal_CreateTrampolineFunction(&ct), "accept VPMASKMOVD memory load");
    check(ct.oldSize==5, "five-byte source prefix remains five bytes after jump-back emission");
    check(!memcmp(code+512,vex,5), "preserve VEX instruction instead of emitting Jcc");
    memcpy(code+64,xbegin,sizeof xbegin);
    check(!MthInternal_CreateTrampolineFunction(&ct), "refuse unhandled relative XBEGIN");
    {
        const BYTE load[]={0x48,0x8b,0x44,0x24,0x60};
        const BYTE stack[]={0x48,0x83,0xec,0x38};
        const BYTE frame[]={0x48,0x89,0xcd};
        memcpy(code+128,load,sizeof(load));
        check(MthInternal_IsUnwindNeutralInstruction(code+128,sizeof(load),0),"allow stack-relative load after a short prologue");
        memcpy(code+128,stack,sizeof(stack));
        check(!MthInternal_IsUnwindNeutralInstruction(code+128,sizeof(stack),0),"refuse undescribed body stack adjustment");
        memcpy(code+128,frame,sizeof(frame));
        check(!MthInternal_IsUnwindNeutralInstruction(code+128,sizeof(frame),5),"refuse body modification of the active frame register");
    }
    byte_alias_cases(code+128);
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
