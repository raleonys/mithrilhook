// SPDX-License-Identifier: GPL-3.0-only
#include <windows.h>
#include <MithrilHook.h>
#include <stdio.h>
#include <string.h>
#ifdef MTH_TEST_ENGINE_SOURCE
#include MTH_TEST_ENGINE_SOURCE
#endif
typedef int (__cdecl *FUNCTION)(void);
static unsigned checks;
static void require(BOOL ok,const char *why)
{++checks;if(!ok){fprintf(stderr,"FAIL: %s\n",why);ExitProcess(1);}}
static void returns(BYTE *code,int value)
{code[0]=0xb8;memcpy(code+1,&value,4);code[5]=0xc3;}
static void setup(BYTE *area,UINT kind,UINT distance,BYTE **a,BYTE **b,int *va,int *vb)
{
    BYTE *source=area+128;
    memset(area,0x90,512);*a=source;*b=source+distance;
    if(kind==0) {returns(source+16,1);*va=*vb=1;}
    else
    {
        source[0]=0x31;source[1]=0xc0;source[2]=0xc3;*va=0;*vb=2;
        if(kind!=3)source[-1]=0x40; /* No alternate hotpatch placement for A. */
        if(kind==1||kind==3) {(*b)[0]=0xeb;(*b)[1]=62;(*b)[2]=0x40;(*b)[3]=0x41;(*b)[4]=0x42;returns(*b+64,2);}
        else returns(*b,2);
    }
    require(FlushInstructionCache(GetCurrentProcess(),area,512),"flush overlap source fixtures");
}
static void conflict(BYTE *area,UINT kind,UINT distance,UINT reverse,BYTE *detourA,BYTE *detourB)
{
    BYTE *a,*b,*first,*second,snapshot[128];int va,vb,originalValue,detourValue;
    LPVOID original=NULL,refused=(LPVOID)(ULONG_PTR)0x1234;
    setup(area,kind,distance,&a,&b,&va,&vb);
    require(((FUNCTION)a)()==va&&((FUNCTION)b)()==vb,"both source entries independently execute before reservation");
    first=reverse?b:a;second=reverse?a:b;originalValue=reverse?vb:va;detourValue=reverse?22:11;
    require(MTH_CreateHook(first,reverse?detourB:detourA,&original)==MTH_OK&&original!=NULL,"reserve first disabled patch owner");
    memcpy(snapshot,area+112,sizeof(snapshot));
    require(MTH_CreateHook(second,reverse?detourA:detourB,&refused)==MTH_ERROR_UNSUPPORTED_FUNCTION,
        "conflicting hook creation refuses before publishing an original");
    require(refused==(LPVOID)(ULONG_PTR)0x1234&&!memcmp(snapshot,area+112,sizeof(snapshot)),"disabled-owner conflict preserves output and all source bytes");
    require(MTH_CreateHook(first,detourA,NULL)==MTH_ERROR_ALREADY_CREATED,"exact duplicate preserves its distinct status");
    require(((FUNCTION)original)()==originalValue,"first original survives refused reservation");
    require(MTH_EnableHook(first)==MTH_OK&&((FUNCTION)first)()==detourValue&&((FUNCTION)original)()==originalValue,"single enable retains first valid jump and original");
    memcpy(snapshot,area+112,sizeof(snapshot));
    require(MTH_CreateHook(second,reverse?detourA:detourB,&refused)==MTH_ERROR_UNSUPPORTED_FUNCTION,"enabled owner also reserves the complete patch range");
    require(refused==(LPVOID)(ULONG_PTR)0x1234&&!memcmp(snapshot,area+112,sizeof(snapshot))&&((FUNCTION)first)()==detourValue,"enabled-owner refusal preserves the first jump");
    require(MTH_DisableHook(first)==MTH_OK,"disable first owner");
    require(MTH_EnableHook(MTH_ALL_HOOKS)==MTH_OK&&((FUNCTION)first)()==detourValue,"all-hooks enable cannot resurrect the refused hook");
    require(MTH_DisableHook(MTH_ALL_HOOKS)==MTH_OK,"all-hooks disable preserves the owned set");
    require(MTH_QueueEnableHook(MTH_ALL_HOOKS)==MTH_OK&&MTH_ApplyQueued()==MTH_OK&&((FUNCTION)first)()==detourValue,"queued apply activates only accepted owners");
    require(MTH_QueueDisableHook(MTH_ALL_HOOKS)==MTH_OK&&MTH_ApplyQueued()==MTH_OK,"queued disable completes");
    require(MTH_RemoveHook(first)==MTH_OK,"retire the reserving owner before reusing its bytes");
    require(MTH_CreateHook(second,reverse?detourA:detourB,&original)==MTH_OK&&original!=NULL,"retirement releases the interval for a new owner");
    require(MTH_EnableHook(second)==MTH_OK&&((FUNCTION)second)()==(reverse?11:22),"new owner can enable after the old owner retires");
    require(MTH_RemoveHook(second)==MTH_OK&&((FUNCTION)a)()==va&&((FUNCTION)b)()==vb,"enabled removal restores both original source entries");
}
static void adjacent(BYTE *area,UINT kind,UINT distance,UINT reverse,BYTE *detourA,BYTE *detourB)
{
    BYTE *a,*b,*first,*second,snapshot[128];int va,vb;LPVOID oa=NULL,ob=NULL;
    setup(area,kind,distance,&a,&b,&va,&vb);memcpy(snapshot,area+112,sizeof(snapshot));
    if(kind==3)
    {
        require(MTH_CreateHook(b,detourB,&ob)==MTH_OK&&MTH_EnableHook(b)==MTH_OK,"reserve and enable the first actual hotpatch");
        require(MTH_CreateHook(a,detourA,&oa)==MTH_OK,"a disjoint alternate hotpatch remains available");
        require(MTH_DisableHook(b)==MTH_OK,"disable initial hotpatch after alternate placement is selected");
    }
    else
    {
        require(MTH_CreateHook(reverse?b:a,reverse?detourB:detourA,reverse?&ob:&oa)==MTH_OK,"first adjacent reservation succeeds");
        require(MTH_CreateHook(reverse?a:b,reverse?detourA:detourB,reverse?&oa:&ob)==MTH_OK,"touching intervals do not overlap");
    }
    require(((FUNCTION)oa)()==va&&((FUNCTION)ob)()==vb,"adjacent originals preserve independent source results");
    require(MTH_EnableHook(a)==MTH_OK&&MTH_EnableHook(b)==MTH_OK&&((FUNCTION)a)()==11&&((FUNCTION)b)()==22,"adjacent individual enables keep both jumps valid");
    require(MTH_DisableHook(MTH_ALL_HOOKS)==MTH_OK&&!memcmp(snapshot,area+112,sizeof(snapshot)),"adjacent all-hooks disable restores all source bytes");
    require(MTH_EnableHook(MTH_ALL_HOOKS)==MTH_OK&&((FUNCTION)a)()==11&&((FUNCTION)b)()==22,"adjacent all-hooks enable supports both owners");
    require(MTH_DisableHook(MTH_ALL_HOOKS)==MTH_OK,"disable adjacent owners before queued activation");
    require(MTH_QueueEnableHook(MTH_ALL_HOOKS)==MTH_OK&&MTH_ApplyQueued()==MTH_OK&&((FUNCTION)a)()==11&&((FUNCTION)b)()==22,"adjacent queued apply keeps both jumps valid");
    first=reverse?b:a;second=reverse?a:b;
    require(MTH_RemoveHook(first)==MTH_OK&&((FUNCTION)second)()==(reverse?11:22),"retiring one adjacent owner preserves the other enabled jump");
    require(MTH_RemoveHook(second)==MTH_OK&&!memcmp(snapshot,area+112,sizeof(snapshot))&&((FUNCTION)a)()==va&&((FUNCTION)b)()==vb,"both retirement orders restore adjacent source and ownership");
}
int main(void)
{
    BYTE *area,*detourA,*detourB;DWORD before,after;UINT reverse,distance;
    require(GetProcessHandleCount(GetCurrentProcess(),&before),"capture overlap handle baseline");
    area=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    require(area!=NULL,"allocate owned overlap fixture");detourA=area+1024;detourB=area+1088;returns(detourA,11);returns(detourB,22);
    require(FlushInstructionCache(GetCurrentProcess(),area+1024,128),"flush independent overlap detours");
    require(MTH_Initialize()==MTH_OK,"initialize overlap engine");
    for(reverse=0;reverse<2;++reverse)
    {
        for(distance=1;distance<=4;++distance)conflict(area,0,distance,reverse,detourA,detourB);
        conflict(area,1,8,reverse,detourA,detourB);
        adjacent(area,2,5,reverse,detourA,detourB);
        adjacent(area,1,10,reverse,detourA,detourB);
        adjacent(area,3,8,reverse,detourA,detourB);
    }
    require(MTH_Uninitialize()==MTH_OK,"complete overlap engine cleanup");
    require(VirtualFree(area,0,MEM_RELEASE),"release overlap fixture storage last");
    require(GetProcessHandleCount(GetCurrentProcess(),&after)&&after==before,"restore overlap handle baseline");
    printf("PASS: %u native overlap reservation/execution/retirement checks\n",checks);return 0;
}
