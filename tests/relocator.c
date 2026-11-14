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

static void internal_call_cases(BYTE *source, BYTE *trampoline)
{
    const BYTE legacy[] = {0,0x2e,0x3e,0x67,0xf2,0xf3};
    const int destinations[] = {-1,0,1,2,3,4,5,64};
    UINT form,site,target,expanded;
    for(form=0;form<26;++form)
    for(site=0;site<5;++site)
    for(target=0;target<sizeof(destinations)/sizeof(destinations[0]);++target)
    {
        BYTE prefix[2];UINT size=0,length;INT32 displacement;
        BOOL accepted;TRAMPOLINE ct;BYTE snapshot[128];
        if(form<6){if(form){prefix[0]=legacy[form];size=1;}}
        else if(form<22){prefix[0]=(BYTE)(0x40+form-6);size=1;}
        else
        {
            prefix[0]=form<24?0x67:0x2e;prefix[1]=0x48;size=2;
            if(form&1){prefix[1]=prefix[0];prefix[0]=0x48;}
        }
        length=size+5;displacement=destinations[target]-(INT32)(site+length);
        accepted=(destinations[target]<0||destinations[target]>=5)&&displacement!=0;
        memset(source,0x90,128);memcpy(source+site,prefix,size);
        source[site+size]=0xe8;memcpy(source+site+size+1,&displacement,4);
        source[site+length]=0xc3;memcpy(snapshot,source,sizeof(snapshot));
        memset(&ct,0,sizeof(ct));ct.pTarget=source;ct.pTrampoline=trampoline;ct.pDetour=source+128;
        check(MthInternal_CreateTrampolineFunction(&ct)==accepted,
            "CALL into the five-byte patch refuses before original publication");
        check(!memcmp(source,snapshot,sizeof(snapshot)),"CALL range admission preserves source bytes");
        if(accepted)
        {
            UINT64 address;memcpy(&address,trampoline+site+8,8);
            check(address==(UINT64)(ULONG_PTR)(source+destinations[target]),
                "outside CALL retains its exact original destination");
        }
    }
    for(expanded=0;expanded<2;++expanded)
    for(target=0;target<5;++target)
    {
        TRAMPOLINE ct;INT32 displacement=(INT32)target-9;
        const BYTE report[]={0xeb,2,0xc3,0x90,0xe8,0xf9,0xff,0xff,0xff,0xb8,42,0,0,0,0xc3};
        memset(source,0x90,128);memcpy(source,report,sizeof(report));
        if(expanded){source[0]=0x74;source[1]=30;source[2]=0x90;}
        memcpy(source+5,&displacement,4);
        memset(&ct,0,sizeof(ct));ct.pTarget=source;ct.pTrampoline=trampoline;ct.pDetour=source+128;
        check(!MthInternal_CreateTrampolineFunction(&ct),
            "forward entry and earlier expansion cannot hide an internal CALL");
    }
}

static void x87_state_cases(BYTE *source,BYTE *trampoline)
{
    const BYTE forms[][2]={
        {0xd8,0xc0},{0xd9,0xee},{0xda,0xc1},{0xdb,0xe3},
        {0xdc,0xc0},{0xdd,0xd8},{0xde,0xc1},{0xdf,0xe0},
        {0xd8,1},{0xd9,1},{0xda,1},{0xdb,1},{0xdc,1},{0xdd,1},{0xde,1},{0xdf,1},
        {0xd9,0x31},{0xd9,0x21},{0xdd,0x31},{0xdd,0x21},
        {0xd9,0x39},{0xd9,0x29},{0xdd,0x39},{0xd9,0xd0}
    };
    const BYTE legacy[]={0,0x66,0x67,0x2e};
    UINT form,prefix,site;
    for(form=0;form<sizeof(forms)/sizeof(forms[0]);++form)
    for(prefix=0;prefix<21;++prefix)
    for(site=0;site<5;++site)
    {
        UINT size=prefix?1:0;BOOL copied=!(prefix==20&&site==4);
        TRAMPOLINE ct;BYTE snapshot[64];
        memset(source,0x90,64);
        if(size)source[site]=prefix<4?legacy[prefix]:prefix<20?(BYTE)(0x40+prefix-4):0x9b;
        memcpy(source+site+size,forms[form],2);source[site+size+2]=0xc3;
        memcpy(snapshot,source,sizeof(snapshot));
        memset(&ct,0,sizeof(ct));ct.pTarget=source;ct.pTrampoline=trampoline;ct.pDetour=source+128;
        check(MthInternal_CreateTrampolineFunction(&ct)==!copied,
            "copied x87 state producers refuse even when observation is outside the prefix");
        check(!memcmp(source,snapshot,sizeof(snapshot)),"x87 refusal preserves source bytes");
    }
    {
        const struct {BYTE bytes[4];UINT length;BOOL accepted;} states[]={
            {{0x0f,0xae,1},3,TRUE},{{0x0f,0xae,9},3,TRUE},
            {{0x48,0x0f,0xae,1},4,TRUE},{{0x48,0x0f,0xae,9},4,TRUE},
            {{0x0f,0xae,0x11},3,TRUE},{{0x0f,0xae,0x19},3,TRUE},
            {{0x0f,0xae,0xe8},3,TRUE},{{0x0f,0xae,0xf0},3,TRUE},{{0x0f,0xae,0xf8},3,TRUE},
            {{0x0f,0xae,0x21},3,FALSE},{{0x0f,0xae,0x29},3,FALSE},{{0x0f,0xae,0x31},3,FALSE},
            {{0x0f,0xc7,0x19},3,FALSE},{{0x0f,0xc7,0x21},3,FALSE},{{0x0f,0xc7,0x29},3,FALSE}
        };
        for(form=0;form<sizeof(states)/sizeof(states[0]);++form)
        for(site=0;site<5;++site)
        {
            TRAMPOLINE ct;memset(source,0x90,64);memcpy(source+site,states[form].bytes,states[form].length);
            source[site+states[form].length+2]=0xc3;
            memset(&ct,0,sizeof(ct));ct.pTarget=source;ct.pTrampoline=trampoline;ct.pDetour=source+128;
            check(MthInternal_CreateTrampolineFunction(&ct)==states[form].accepted,
                "fixed state save/restore and fences stay supported; extended state layouts refuse");
        }
    }
    {
        const BYTE report[]={0xd9,0xee,0xd9,0x31,0xdd,0xd8,0xc3};TRAMPOLINE ct;
        memset(source,0x90,64);memcpy(source+5,report,sizeof(report));
        memset(&ct,0,sizeof(ct));ct.pTarget=source;ct.pTrampoline=trampoline;ct.pDetour=source+128;
        check(MthInternal_CreateTrampolineFunction(&ct),"x87 operations entirely after the copied prefix remain at source IPs");
        memset(source,0x90,64);source[0]=0xd9;source[1]=0xee;source[8]=0xd9;source[9]=0x31;source[10]=0xc3;
        check(!MthInternal_CreateTrampolineFunction(&ct),"a later source FNSTENV cannot observe an accepted copied x87 producer");
    }
}

static void undefined_trap_cases(BYTE *source,BYTE *trampoline)
{
    const BYTE opcodes[]={0x0b,0xb9,0xff};
    const BYTE prefixes[]={0,0x66,0x67,0x2e,0xf2,0xf3,0x64,0x65};
    UINT kind,prefix,site,modrm;
    for(kind=0;kind<3;++kind)
    for(prefix=0;prefix<24;++prefix)
    for(site=0;site<5;++site)
    for(modrm=0;modrm<(kind?256U:1U);++modrm)
    {
        UINT n=site;TRAMPOLINE ct;BYTE snapshot[64];
        memset(source,0x90,64);
        if(prefix)source[n++]=prefix<8?prefixes[prefix]:(BYTE)(0x40+prefix-8);
        source[n++]=0x0f;source[n++]=opcodes[kind];
        if(kind)source[n++]=(BYTE)modrm;
        source[24]=0xc3;memcpy(snapshot,source,sizeof(snapshot));
        memset(&ct,0,sizeof(ct));ct.pTarget=source;ct.pTrampoline=trampoline;ct.pDetour=source+128;
        check(!MthInternal_CreateTrampolineFunction(&ct),"all copied UD0/UD1/UD2 encodings refuse");
        check(!memcmp(source,snapshot,sizeof(snapshot)),"undefined-trap refusal preserves source bytes");
    }
    for(kind=0;kind<3;++kind)
    for(site=5;site<10;++site)
    {
        TRAMPOLINE ct;memset(source,0x90,64);source[site]=0x0f;source[site+1]=opcodes[kind];source[site+2]=0xc0;source[site+3]=0xc3;
        memset(&ct,0,sizeof(ct));ct.pTarget=source;ct.pTrampoline=trampoline;ct.pDetour=source+128;
        check(MthInternal_CreateTrampolineFunction(&ct),"a deliberate trap beyond the copied prefix stays at its source IP");
    }
}

static void transition_cases(BYTE *source,BYTE *trampoline)
{
    const struct {BYTE bytes[8];UINT size;} gates[]={
        {{0x0f,0x05},2},{{0x0f,0x07},2},{{0x0f,0x34},2},{{0x0f,0x35},2},{{0x0f,0xaa},2},
        {{0xcc},1},{{0xcd,0x2e},2},{{0xce},1},{{0xcf},1},{{0xf1},1},
        {{0xcb},1},{{0xca,0,0},3},{{0x9a,0,0,0,0,0,0},7},{{0xea,0,0,0,0,0,0},7},
        {{0xff,0x19},2},{{0xff,0x29},2}
    };
    const BYTE prefixes[]={0,0x66,0x67,0x2e,0xf2,0xf3};
    UINT kind,prefix,site;
    for(kind=0;kind<sizeof(gates)/sizeof(gates[0]);++kind)
    for(prefix=0;prefix<22;++prefix)
    for(site=0;site<5;++site)
    {
        UINT size=prefix?1:0;TRAMPOLINE ct;BYTE snapshot[64];
        memset(source,0x90,64);
        if(size)source[site]=prefix<6?prefixes[prefix]:(BYTE)(0x40+prefix-6);
        memcpy(source+site+size,gates[kind].bytes,gates[kind].size);
        source[site+size+gates[kind].size]=0xc3;memcpy(snapshot,source,sizeof(snapshot));
        memset(&ct,0,sizeof(ct));ct.pTarget=source;ct.pTrampoline=trampoline;ct.pDetour=source+128;
        check(!MthInternal_CreateTrampolineFunction(&ct),"copied system transitions refuse before original publication");
        check(!memcmp(source,snapshot,sizeof(snapshot)),"transition refusal preserves source bytes");
    }
    for(site=5;site<10;++site)
    {
        TRAMPOLINE ct;memset(source,0x90,64);source[site]=0x0f;source[site+1]=5;source[site+2]=0xc3;
        memset(&ct,0,sizeof(ct));ct.pTarget=source;ct.pTrampoline=trampoline;ct.pDetour=source+128;
        check(MthInternal_CreateTrampolineFunction(&ct),"a source-resident SYSCALL after the copied prefix keeps its original IP");
    }
    {
        const struct {BYTE bytes[4];UINT size;} controls[]={{{0xc3},1},{{0xc2,4,0},3},{{0x0f,0x1f,0},3},{{0x90,0x90,0x90,0x90},4}};
        for(kind=0;kind<sizeof(controls)/sizeof(controls[0]);++kind)
        {
            TRAMPOLINE ct;memset(source,0x90,64);memcpy(source,controls[kind].bytes,controls[kind].size);source[8]=0xc3;
            memset(&ct,0,sizeof(ct));ct.pTarget=source;ct.pTrampoline=trampoline;ct.pDetour=source+128;
            check(MthInternal_CreateTrampolineFunction(&ct),"ordinary near returns and neutral instructions retain their existing contract");
        }
    }
}

static void rip_patch_cases(BYTE *source, BYTE *trampoline)
{
    static const struct { BYTE bytes[16]; UINT length; BOOL accepted; } cases[] = {
        {{0x48,0x0f,0xa3,0x0d,56,0,0,0,0xc3},9,FALSE}, /* BT with register bit index. */
        {{0x48,0x0f,0xab,0x0d,56,0,0,0,0xc3},9,FALSE},
        {{0x48,0x0f,0xb3,0x0d,56,0,0,0,0xc3},9,FALSE},
        {{0x48,0x0f,0xbb,0x0d,56,0,0,0,0xc3},9,FALSE},
        {{0x0f,0xae,0x05,0x79,0xff,0xff,0xff,0xc3},8,FALSE}, /* FXSAVE source-128, size 512. */
        {{0x0f,0xae,0x0d,0x79,0xff,0xff,0xff,0xc3},8,FALSE},
        {{0x0f,0xae,0x25,57,0,0,0,0xc3},8,FALSE}, /* Variable-sized XSAVE. */
        {{0x64,0x8b,0x05,57,0,0,0,0xc3},8,FALSE},
        {{0x65,0x8b,0x05,57,0,0,0,0xc3},8,FALSE},
        {{0xc5,0xf9,0x6f,0x05,56,0,0,0,0xc3},9,FALSE},
        {{0x8f,0xe9,0x78,0x92,0x05,55,0,0,0,0xc3},10,FALSE}, /* XOP, not legacy POP. */
        {{0x66,0x8b,0x05,0xf8,0xff,0xff,0xff,0xc3},8,FALSE}, /* Word partly overlaps. */
        {{0x8b,0x05,0xf7,0xff,0xff,0xff,0xc3},7,FALSE},
        {{0x89,0x05,0xfa,0xff,0xff,0xff,0xc3},7,FALSE},
        {{0x0f,0xb6,0x05,0xf8,0xff,0xff,0xff,0xc3},8,TRUE}, /* Byte ends at patch start. */
        {{0x8b,0x05,0xf6,0xff,0xff,0xff,0xc3},7,TRUE}, /* Dword ends at patch start. */
        {{0x0f,0xb6,0x05,0xfe,0xff,0xff,0xff,0xc3},8,TRUE}, /* Starts at patch end. */
        {{0x64,0x48,0x8d,0x05,0xf8,0xff,0xff,0xff,0xc3},9,TRUE},
        {{0x65,0x48,0x8d,0x05,0xf8,0xff,0xff,0xff,0xc3},9,TRUE},
        {{0x0f,0x1f,0x05,0xf9,0xff,0xff,0xff,0xc3},8,TRUE},
        {{0x0f,0xae,0x05,0xf9,0xfd,0xff,0xff,0xc3},8,TRUE}, /* 512-byte range ends at entry. */
        {{0x0f,0xae,0x05,57,0,0,0,0xc3},8,TRUE}
    };
    UINT index;
    for (index = 0; index < sizeof(cases)/sizeof(cases[0]); ++index)
    {
        TRAMPOLINE ct;
        memset(source,0x90,128); memcpy(source,cases[index].bytes,cases[index].length);
        memset(&ct,0,sizeof(ct)); ct.pTarget=source; ct.pTrampoline=trampoline; ct.pDetour=source+128;
        check(MthInternal_CreateTrampolineFunction(&ct)==cases[index].accepted,
            "RIP access requires a proven range; indexed, unknown and segment-dependent forms refuse");
    }
}

static void check_push_layout(BYTE *source,BYTE *trampoline,const BYTE *prefix,UINT prefixSize,UINT width)
{
    int addresses[7]={-(int)width,1-(int)width,-1,0,4,5,64};
    UINT index;
    for(index=0;index<7;++index)
    {
        TRAMPOLINE ct;
        UINT length=prefixSize+6;
        INT32 displacement=addresses[index]-(INT32)length,relocated;
        BOOL overlap=addresses[index]<5&&addresses[index]+(int)width>0;
        memset(source,0x90,128);memcpy(source,prefix,prefixSize);
        source[prefixSize]=0xff;source[prefixSize+1]=0x35;
        memcpy(source+prefixSize+2,&displacement,4);source[length]=0xc3;
        memset(&ct,0,sizeof(ct));ct.pTarget=source;ct.pTrampoline=trampoline;ct.pDetour=source+128;
        check(MthInternal_CreateTrampolineFunction(&ct)==!overlap,
            "PUSH range uses architectural REX.W/66 precedence at both patch boundaries");
        if(!overlap)
        {
            memcpy(&relocated,trampoline+prefixSize+2,4);
            check((INT64)(trampoline+length)+relocated==(INT64)source+addresses[index],
                "disjoint PUSH retains its complete original effective address");
            check(!memcmp(source,trampoline,prefixSize+2),"PUSH fixup preserves effective prefix order and opcode");
        }
    }
}

static void push_prefix_cases(BYTE *source,BYTE *trampoline)
{
    static const struct {BYTE prefix[4];UINT size,width;} special[]={
        {{0},0,8},{{0x66},1,2},{{0x48},1,8},{{0x66,0x48},2,8},
        {{0x48,0x66},2,2},{{0x66,0x48,0x66},3,2},{{0x48,0x66,0x48},3,8},
        {{0x66,0x48,0x40},3,2},{{0x66,0x40,0x48},3,8}
    };
    UINT rex,order,index;
    for(index=0;index<sizeof(special)/sizeof(special[0]);++index)
        check_push_layout(source,trampoline,special[index].prefix,special[index].size,special[index].width);
    for(rex=0;rex<16;++rex)
    for(order=0;order<4;++order)
    {
        BYTE prefix[3];UINT size,width;
        if(order==0){prefix[0]=(BYTE)(0x40+rex);size=1;width=8;}
        else if(order==1){prefix[0]=0x66;prefix[1]=(BYTE)(0x40+rex);size=2;width=(rex&8)?8:2;}
        else if(order==2){prefix[0]=(BYTE)(0x40+rex);prefix[1]=0x66;size=2;width=2;}
        else{prefix[0]=0x66;prefix[1]=0x48;prefix[2]=(BYTE)(0x40+rex);size=3;width=(rex&8)?8:2;}
        check_push_layout(source,trampoline,prefix,size,width);
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
    {
        const BYTE self[] = {0x8B,0x05,0xFA,0xFF,0xFF,0xFF,0xC3};
        const BYTE overlap[] = {0x8B,0x05,0xF9,0xFF,0xFF,0xFF,0xC3};
        const BYTE lea[] = {0x48,0x8D,0x05,0xF9,0xFF,0xFF,0xFF,0xC3};
        const BYTE outside[] = {0x8B,0x05,0x01,0x00,0x00,0x00,0xC3,0x2A,0x00,0x00,0x00};
        memset(code + 64, 0x90, 64);
        memcpy(code + 64, self, sizeof(self));
        check(!MthInternal_CreateTrampolineFunction(&ct),
            "refuse a RIP-relative load of the bytes the hook jump will overwrite");
        memcpy(code + 64, overlap, sizeof(overlap));
        check(!MthInternal_CreateTrampolineFunction(&ct),
            "refuse a RIP-relative load that only partly covers the hook patch");
        memcpy(code + 64, lea, sizeof(lea));
        check(MthInternal_CreateTrampolineFunction(&ct),
            "LEA of the patched entry keeps the address and remains publishable");
        memcpy(code + 64, outside, sizeof(outside));
        check(MthInternal_CreateTrampolineFunction(&ct),
            "RIP-relative load completely outside the hook patch remains publishable");
    }
    memcpy(code+64,vex,sizeof vex);
    check(MthInternal_CreateTrampolineFunction(&ct), "accept VPMASKMOVD memory load");
    check(ct.oldSize==5, "five-byte source prefix remains five bytes after jump-back emission");
    check(!memcmp(code+512,vex,5), "preserve VEX instruction instead of emitting Jcc");
    memcpy(code+64,xbegin,sizeof xbegin);
    check(!MthInternal_CreateTrampolineFunction(&ct), "refuse unhandled relative XBEGIN");
    internal_branch_cases(code + 64, code + 512);
    internal_call_cases(code + 1024, code + 512);
    x87_state_cases(code + 1024, code + 512);
    transition_cases(code + 1024, code + 512);
    undefined_trap_cases(code + 1024, code + 512);
    rip_patch_cases(code + 1024, code + 512);
    push_prefix_cases(code + 1024, code + 512);
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
