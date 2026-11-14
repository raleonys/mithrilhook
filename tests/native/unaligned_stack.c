// SPDX-License-Identifier: GPL-3.0-only
#include <windows.h>
#include <MithrilHook.h>
#include <stdio.h>
#include <string.h>

static unsigned checks;
static void require(BOOL ok,const char *why)
{++checks;if(!ok){fprintf(stderr,"FAIL: %s\n",why);ExitProcess(1);}}

typedef struct {HANDLE ready,stop;} WORKER;
static DWORD WINAPI worker(LPVOID input)
{
    WORKER *state=(WORKER*)input;volatile BYTE padding[4096];UINT i;
    /* Keep sufficient real, committed stack above the saved SP for both read
     * boundaries. This worker never receives a target/original pointer. */
    for(i=0;i<sizeof(padding);++i)padding[i]=0xa5;
    if(!SetEvent(state->ready)||WaitForSingleObject(state->stop,20000)!=WAIT_OBJECT_0)return 1;
    for(i=0;i<sizeof(padding);++i)if(padding[i]!=0xa5)return 2;
    return 0x73;
}

static void owned_stack_range(ULONG_PTR start,SIZE_T bytes)
{
    ULONG_PTR cursor=start,end=start+bytes,allocation=0;
    require(end>start,"native stack snapshot has bounded arithmetic");
    while(cursor<end)
    {
        MEMORY_BASIC_INFORMATION region;ULONG_PTR limit;
        require(VirtualQuery((LPCVOID)cursor,&region,sizeof(region))==sizeof(region),"query real peer stack snapshot");
        if(!allocation)allocation=(ULONG_PTR)region.AllocationBase;
        require((ULONG_PTR)region.AllocationBase==allocation&&region.State==MEM_COMMIT&&
            !(region.Protect&(PAGE_GUARD|PAGE_NOACCESS)),"snapshot remains inside one readable committed stack allocation");
        limit=(ULONG_PTR)region.BaseAddress+region.RegionSize;
        require(limit>cursor,"native stack region advances");cursor=limit<end?limit:end;
    }
}

static void busy_at(BYTE *source,LPVOID original,ULONG_PTR sp,const BYTE *backup,SIZE_T size,SIZE_T offset,UINT interior)
{
    ULONG_PTR value=(ULONG_PTR)original+interior;SIZE_T copied=0;
    BYTE image[16];MEMORY_BASIC_INFORMATION region;MTH_STATUS removal,shutdown;
    require(offset+sizeof(value)<=size,"real unaligned owner fits the saved stack window");
    memcpy(image,source,sizeof(image));
    require(WriteProcessMemory(GetCurrentProcess(),(LPVOID)(sp+offset),&value,sizeof(value),&copied)&&copied==sizeof(value),
        "place actual trampoline pointer in real peer stack bytes");
    removal=MTH_RemoveHook(source);shutdown=MTH_Uninitialize();
    /* The peer stays externally suspended. Restore its entire exact window
     * before reporting any failed oracle; it never executes edited bytes. */
    require(WriteProcessMemory(GetCurrentProcess(),(LPVOID)sp,backup,size,&copied)&&copied==size,"restore exact real stack snapshot after each observation");
    require(removal==MTH_ERROR_MEMORY_PROTECT,"real unaligned stack owner blocks target-specific removal");
    require(shutdown==MTH_ERROR_MEMORY_PROTECT,"real unaligned stack owner blocks whole-engine shutdown");
    require(VirtualQuery(original,&region,sizeof(region))==sizeof(region)&&region.State==MEM_COMMIT,
        "real unaligned refusal preserves the occupied allocation");
    require(!memcmp(source,image,sizeof(image)),"real unaligned refusals preserve exact source bytes");
}

int main(void)
{
    const SIZE_T chunk=64*sizeof(ULONG_PTR);
    BYTE backup[128*sizeof(ULONG_PTR)+2*sizeof(ULONG_PTR)];
    BYTE *source;LPVOID original=NULL;WORKER state;HANDLE thread;CONTEXT saved;
    DWORD before,after,code;SIZE_T copied=0,offset,boundary;ULONG_PTR sp;
    require(GetProcessHandleCount(GetCurrentProcess(),&before),"capture native unaligned handle baseline");
    state.ready=CreateEventW(NULL,TRUE,FALSE,NULL);state.stop=CreateEventW(NULL,TRUE,FALSE,NULL);
    require(state.ready!=NULL&&state.stop!=NULL,"create bounded unaligned worker events");
    source=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    require(source!=NULL,"allocate owned native unaligned source");memset(source,0x90,4096);source[16]=source[64]=0xc3;
    require(MTH_Initialize()==MTH_OK&&MTH_CreateHook(source,source+64,&original)==MTH_OK&&original!=NULL,"publish disabled native unaligned original");
    thread=CreateThread(NULL,0,worker,&state,0,NULL);require(thread!=NULL,"start pointer-free real peer");
    require(WaitForSingleObject(state.ready,10000)==WAIT_OBJECT_0,"wait for committed real stack padding");
    require(SuspendThread(thread)==0,"own exactly one external peer suspension");
    memset(&saved,0,sizeof(saved));saved.ContextFlags=CONTEXT_FULL;
    require(GetThreadContext(thread,&saved),"capture actual peer context before any edits");
#if defined(_M_X64) || defined(__x86_64__)
    sp=(ULONG_PTR)saved.Rsp;
#else
    sp=(ULONG_PTR)saved.Esp;
#endif
    owned_stack_range(sp,sizeof(backup));
    require(ReadProcessMemory(GetCurrentProcess(),(LPCVOID)sp,backup,sizeof(backup),&copied)&&copied==sizeof(backup),"save exact real stack bytes across two read boundaries");
    for(offset=0;offset<sizeof(ULONG_PTR);++offset)
        busy_at(source,original,sp,backup,sizeof(backup),offset,0);
    for(boundary=chunk;boundary<=2*chunk;boundary+=chunk)
        for(offset=1;offset<sizeof(ULONG_PTR);++offset)
            busy_at(source,original,sp,backup,sizeof(backup),boundary-offset,1);
    require(SuspendThread(thread)==1,"engine repays every suspension while preserving the external owner");
    require(ResumeThread(thread)==2,"repay only inspection suspension");
    require(SetThreadContext(thread,&saved),"restore exact original peer context before resumption");
    require(SetEvent(state.stop),"allow restored worker to drain");
    require(ResumeThread(thread)==1,"release final external suspension after full restoration");
    require(WaitForSingleObject(thread,10000)==WAIT_OBJECT_0&&GetExitCodeThread(thread,&code)&&code==0x73,
        "join restored worker with exact padding and successful completion");
    require(CloseHandle(thread)&&CloseHandle(state.ready)&&CloseHandle(state.stop),"close all exact unaligned worker handles");
    require(MTH_RemoveHook(source)==MTH_OK,"drained original retires successfully on its first attempt");
    require(MTH_Uninitialize()==MTH_OK,"drained engine releases every owner");
    require(VirtualFree(source,0,MEM_RELEASE),"release native source storage last");
    require(GetProcessHandleCount(GetCurrentProcess(),&after)&&after==before,"restore native unaligned handle baseline");
    printf("PASS: %u native unaligned stack ownership/refusal/boundary/cleanup checks\n",checks);return 0;
}
