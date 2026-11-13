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

static void internal_branch_cases(BYTE *source, BYTE *trampoline)
{
    UINT expanded, kind, prefix, target;
    const BYTE prefixes[] = {0, 0x2e, 0x67, 0x66};
    const UINT destinations[] = {0, 2, 3, 4};
    for (expanded = 0; expanded < 2; ++expanded)
    for (kind = 0; kind < 38; ++kind)
    for (prefix = 0; prefix < sizeof(prefixes); ++prefix)
    for (target = 0; target < sizeof(destinations)/sizeof(destinations[0]); ++target)
    {
        TRAMPOLINE ct;
        UINT n = 4, width = kind < 21 ? 1 : 4;
        INT32 displacement, actual;
        UINT branchNew = expanded ? 18 : 4;
        UINT targetNew = expanded && destinations[target] ? destinations[target] + 14 : destinations[target];
        if (prefix == 3 && width == 4) continue; /* Separate 66-near refusal contract. */
        memset(source, 0x90, 256);
        if (expanded) { source[0] = 0x74; source[1] = 30; }
        if (prefix) source[n++] = prefixes[prefix];
        if (kind < 16) source[n++] = (BYTE)(0x70 + kind);
        else if (kind == 16) source[n++] = 0xeb;
        else if (kind < 21) source[n++] = (BYTE)(0xe0 + kind - 17);
        else if (kind < 37) { source[n++] = 0x0f; source[n++] = (BYTE)(0x80 + kind - 21); }
        else source[n++] = 0xe9;
        displacement = (INT32)destinations[target] - (INT32)(n + width);
        if (width == 1) source[n] = (BYTE)(INT8)displacement;
        else memcpy(source + n, &displacement, 4);
        n += width;
        memset(&ct, 0, sizeof(ct));
        ct.pTarget = source; ct.pTrampoline = trampoline; ct.pDetour = source + 128;
        check(MthInternal_CreateTrampolineFunction(&ct), "accept mapped internal JMP/Jcc/LOOP layout");
        actual = 0;
        if (width == 1) actual = (INT8)trampoline[branchNew + n - 4 - 1];
        else memcpy(&actual, trampoline + branchNew + n - 4 - width, 4);
        check((INT32)(branchNew + n - 4) + actual == (INT32)targetNew,
            "internal branch resolves to its relocated instruction boundary");
        check(!memcmp(source + 4, trampoline + branchNew, n - 4 - width),
            "internal fixup preserves prefixes and branch opcode");
    }
    {
        TRAMPOLINE ct;
        const BYTE loop[] = {0x74, 6, 0xff, 0xc1, 0x75, 0xfa, 0x90, 0x90, 0xb8, 42, 0, 0, 0, 0xc3};
        memcpy(source, loop, sizeof(loop));
        memset(&ct, 0, sizeof(ct)); ct.pTarget = source; ct.pTrampoline = trampoline; ct.pDetour = source + 128;
        check(MthInternal_CreateTrampolineFunction(&ct), "accept exact review-13 loop");
        check(trampoline[18] == 0x75 && (INT8)trampoline[19] == -20,
            "review-13 backward JNE returns to trampoline start rather than address data");
        source[5] = 0xfb; /* source+1: the first JE's immediate byte. */
        check(!MthInternal_CreateTrampolineFunction(&ct), "refuse an internal target inside a decoded Jcc");
        source[5] = 0xfd; /* source+3: INC's ModR/M byte. */
        check(!MthInternal_CreateTrampolineFunction(&ct), "refuse an internal target inside a decoded INC");
    }
    {
        TRAMPOLINE ct;
        const BYTE forward[] = {0xeb, 2, 0x90, 0x90, 0x90, 0xc3};
        memset(source, 0x90, 64); memcpy(source, forward, sizeof(forward));
        memset(&ct, 0, sizeof(ct)); ct.pTarget = source; ct.pTrampoline = trampoline; ct.pDetour = source + 128;
        check(MthInternal_CreateTrampolineFunction(&ct) && trampoline[0] == 0xeb && trampoline[1] == 2,
            "preserve plain forward internal branch control");
        source[0] = 0x74; source[1] = 30; source[2] = 0xeb; source[3] = 0;
        check(MthInternal_CreateTrampolineFunction(&ct) && trampoline[16] == 0xeb && trampoline[17] == 0,
            "preserve a forward internal target after an earlier expansion");
        source[0] = 0xeb; source[1] = 2; source[2] = 0x74; source[3] = 28;
        check(!MthInternal_CreateTrampolineFunction(&ct),
            "retain conservative refusal of length changes inside a pending forward span");
    }
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
    internal_branch_cases(code + 64, code + 512);
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
    {
        UINT payload,reg;
        for(payload=0;payload<256;++payload)
        for(reg=0;reg<8;++reg)
        {
            BYTE rex2[]={0xd5,(BYTE)payload,(BYTE)(0xb0+reg),0x10};
            memcpy(code+128,rex2,sizeof(rex2));
            check(!MthInternal_IsUnwindNeutralInstruction(code+128,sizeof(rex2),0),
                "no REX2/APX stream is inferred neutral from legacy byte aliases");
        }
    }
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
