// SPDX-License-Identifier: GPL-3.0-only

/* Exercise the actual patched engine, injecting only peer-thread OS failures. */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <MithrilHook.h>

#if defined(_M_X64) || defined(__x86_64__)
#define PEER_CONTEXT_IP(c) ((c)->Rip)
#define PEER_CONTEXT_SP(c) ((c)->Rsp)
#else
#define PEER_CONTEXT_IP(c) ((c)->Eip)
#define PEER_CONTEXT_SP(c) ((c)->Esp)
#endif
static BOOL fail_enumeration, fail_duplicate, peer_dead, peer_invalid, include_current, fail_reallocate, return_second_cursor, fail_second_cursor;
static int checks, enumeration, resumes, closes, cursor_closes;
static BOOL unavailable, fail_resume, fail_close, fail_heap, fail_context, fail_set_context, fail_suspend, fail_cursor, fail_array;
static HANDLE cursor_handle = (HANDLE)(ULONG_PTR)0x4321;
static HANDLE peer_handle = (HANDLE)(ULONG_PTR)0x4322;
static HANDLE second_cursor_handle = (HANDLE)(ULONG_PTR)0x4323;
static DWORD_PTR peer_ip;
static int context_writes;
static DWORD_PTR peer_stack[4];
static SIZE_T WINAPI query_peer_stack(LPCVOID address,PMEMORY_BASIC_INFORMATION out,SIZE_T size) {
    ULONG_PTR at=(ULONG_PTR)address,start=(ULONG_PTR)peer_stack,end=start+sizeof(peer_stack);
    if(at>=start && at<=end){memset(out,0,sizeof(*out));out->BaseAddress=(LPVOID)(at==end?end:start);
        out->AllocationBase=out->BaseAddress;out->RegionSize=at==end?8:sizeof(peer_stack);
        out->State=MEM_COMMIT;out->Protect=PAGE_READWRITE;return sizeof(*out);}
    return VirtualQuery(address,out,size);
}
static void require(BOOL ok, const char* message) {
    ++checks;
    if (!ok) { fprintf(stderr, "FAIL: %s\n", message); exit(1); }
}
static LONG NTAPI fake_next(HANDLE process,HANDLE previous,ACCESS_MASK access,ULONG attributes,ULONG flags,PHANDLE next) {
    (void)process;(void)attributes;(void)flags;++enumeration;
    if(access!=(THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT|THREAD_QUERY_INFORMATION|THREAD_SET_CONTEXT)){*next=NULL;return (LONG)0xC0000022L;}
    if(fail_enumeration){*next=NULL;return (LONG)0xC0000022L;}
    if (!previous) {*next=cursor_handle;return 0;}
    if(return_second_cursor){*next=second_cursor_handle;return 0;}
    *next=NULL;return (LONG)0x8000001AL;
}
static FARPROC WINAPI lookup(HMODULE module,LPCSTR name) {
    if (!strcmp(name,"NtGetNextThread"))return unavailable?NULL:(FARPROC)fake_next;
    return GetProcAddress(module,name);
}
static DWORD WINAPI thread_id(HANDLE thread) {
    return thread==cursor_handle?GetCurrentThreadId()+(include_current?0:1):GetThreadId(thread);
}
static BOOL WINAPI duplicate(HANDLE source,HANDLE thread,HANDLE target,LPHANDLE result,DWORD access,BOOL inherit,DWORD flags) {
    if(thread==cursor_handle){if(fail_duplicate){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}*result=peer_handle;return TRUE;}
    return DuplicateHandle(source,thread,target,result,access,inherit,flags);
}
static DWORD WINAPI suspend_peer(HANDLE thread) {
    if(thread==peer_handle){if(fail_suspend){SetLastError(ERROR_ACCESS_DENIED);return (DWORD)-1;}return 0;}
    return SuspendThread(thread);
}
static DWORD WINAPI resume_peer(HANDLE thread) {
    if(thread==peer_handle){++resumes;if(fail_resume){SetLastError(ERROR_ACCESS_DENIED);return (DWORD)-1;}return 1;}
    return ResumeThread(thread);
}
static BOOL WINAPI close_peer(HANDLE thread) {
    if(thread==second_cursor_handle){if(fail_second_cursor){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}return TRUE;}
    if(thread==cursor_handle){++cursor_closes;if(fail_cursor){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}return TRUE;}
    if(thread==peer_handle){++closes;if(fail_close){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}return TRUE;}
    return CloseHandle(thread);
}
static BOOL WINAPI context_peer(HANDLE thread,LPCONTEXT context) {
    if(thread==peer_handle){DWORD flags=context->ContextFlags;if(fail_context){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
        memset(context,0,sizeof(*context));context->ContextFlags=flags;PEER_CONTEXT_SP(context)=(DWORD_PTR)(ULONG_PTR)peer_stack;
        PEER_CONTEXT_IP(context)=peer_ip;return TRUE;}
    return GetThreadContext(thread,context);
}
static BOOL WINAPI update_context_peer(HANDLE thread,const CONTEXT* context) {
    if(thread==peer_handle){if(fail_set_context){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}peer_ip=PEER_CONTEXT_IP(context);++context_writes;return TRUE;}
    return SetThreadContext(thread,context);
}
static BOOL WINAPI exit_code(HANDLE thread,LPDWORD code) {
    if(thread==peer_handle){if(peer_invalid){SetLastError(ERROR_INVALID_HANDLE);return FALSE;}*code=peer_dead?0:STILL_ACTIVE;return TRUE;}
    return GetExitCodeThread(thread,code);
}
static BOOL WINAPI release_heap(HANDLE heap,DWORD flags,LPVOID memory) {
    if(fail_heap&&memory){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    return HeapFree(heap,flags,memory);
}
static LPVOID WINAPI allocate_heap(HANDLE heap,DWORD flags,SIZE_T bytes) {
    if(fail_array)return NULL;
    return HeapAlloc(heap,flags,bytes);
}
static LPVOID WINAPI reallocate_heap(HANDLE heap,DWORD flags,LPVOID memory,SIZE_T bytes) {
    if(fail_reallocate)return NULL;
    return HeapReAlloc(heap,flags,memory,bytes);
}
#define HeapReAlloc reallocate_heap
#define GetProcAddress lookup
#define GetThreadId thread_id
#define DuplicateHandle duplicate
#define SuspendThread suspend_peer
#define ResumeThread resume_peer
#define CloseHandle close_peer
#define GetThreadContext context_peer
#define SetThreadContext update_context_peer
#define GetExitCodeThread exit_code
#define HeapFree release_heap
#define HeapAlloc allocate_heap
#define VirtualQuery query_peer_stack
/* CMake's include path names the verified build copy, never the original. */
#ifndef MTH_TEST_ENGINE_SOURCE
#define MTH_TEST_ENGINE_SOURCE "hook.c"
#endif
#include MTH_TEST_ENGINE_SOURCE

static void reset_faults(void) {
    unavailable=fail_resume=fail_close=fail_heap=fail_context=fail_set_context=fail_suspend=fail_cursor=fail_array=FALSE;
}
static void single_hook_ip_relocation(void) {
    unsigned char* target=(unsigned char*)VirtualAlloc(NULL,64,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    LPVOID trampoline=NULL;
    int writes;
    require(target!=NULL,"allocate executable hook fixture; never execute its bytes");
    memset(target,0x90,64);target[16]=0xc3;target[32]=0xc3;
    require(MTH_CreateHook(target,target+32,&trampoline)==MTH_OK&&trampoline!=NULL,"create actual single hook and trampoline");
    peer_ip=(DWORD_PTR)(ULONG_PTR)(target+2);writes=context_writes;
    fail_set_context=TRUE;
    require(MTH_EnableHook(target)==MTH_ERROR_MEMORY_PROTECT,"failed peer SetThreadContext rejects single enable");
    require(target[0]==0x90&&peer_ip==(DWORD_PTR)(ULONG_PTR)(target+2)&&context_writes==writes&&
        !HasRetainedThreadOwnership(),"failed enable does not publish patch, relocate IP or leak peer");
    fail_set_context=FALSE;
    require(MTH_EnableHook(target)==MTH_OK,"enable actual single hook after SetThreadContext retry");
    require(peer_ip==(DWORD_PTR)(ULONG_PTR)((unsigned char*)trampoline+2)&&context_writes==writes+1,"single enable maps target IP to trampoline");
    require(target[0]==0xe9,"single enable patches target");
    fail_context=TRUE;
    require(MTH_DisableHook(target)==MTH_ERROR_MEMORY_PROTECT,"unresolved peer context rejects single disable");
    require(target[0]==0xe9&&peer_ip==(DWORD_PTR)(ULONG_PTR)((unsigned char*)trampoline+2),"failed disable preserves live patch and peer IP");
    fail_context=FALSE;writes=context_writes;
    fail_set_context=TRUE;
    require(MTH_DisableHook(target)==MTH_ERROR_MEMORY_PROTECT,"failed peer SetThreadContext rejects single disable");
    require(target[0]==0xe9&&peer_ip==(DWORD_PTR)(ULONG_PTR)((unsigned char*)trampoline+2)&&
        context_writes==writes&&!HasRetainedThreadOwnership(),
        "failed disable retains live patch and peer IP without leaking thread owners");
    fail_set_context=FALSE;
    require(MTH_DisableHook(target)==MTH_OK,"disable actual single hook after context retry");
    require(peer_ip==(DWORD_PTR)(ULONG_PTR)(target+2)&&context_writes==writes+1,"single disable maps trampoline IP back to target");
    require(target[0]==0x90,"single disable restores target bytes");
    require(!HasRetainedThreadOwnership(),"single disable drains peer ownership");
    require(MTH_RemoveHook(target)==MTH_OK,"remove disabled hook after relocation");
    require(VirtualFree(target,0,MEM_RELEASE),"release hook fixture after removal");
    peer_ip=0;
}
static void queued_and_all_hook_ip_relocation(void) {
    unsigned char* memory=(unsigned char*)VirtualAlloc(NULL,128,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    unsigned char* first=memory;
    unsigned char* second;
    LPVOID first_trampoline=NULL, second_trampoline=NULL;
    int writes;
    require(memory!=NULL,"allocate executable two-hook fixture; never call it");
    second=memory+64;
    memset(memory,0x90,128);
    first[16]=0xc3;first[32]=0xc3;second[16]=0xc3;second[32]=0xc3;
    require(MTH_CreateHook(first,first+32,&first_trampoline)==MTH_OK&&first_trampoline!=NULL,
        "create first queued hook");
    require(MTH_CreateHook(second,second+32,&second_trampoline)==MTH_OK&&second_trampoline!=NULL,
        "create second queued hook");
    peer_ip=(DWORD_PTR)(ULONG_PTR)(first+2);writes=context_writes;
    require(MTH_QueueEnableHook(first)==MTH_OK&&MTH_QueueEnableHook(second)==MTH_OK,
        "queue enable for two distinct hooks");
    require(MTH_ApplyQueued()==MTH_OK,"apply queued two-hook enable");
    require(peer_ip==(DWORD_PTR)(ULONG_PTR)((unsigned char*)first_trampoline+2)&&
        context_writes==writes+1&&first[0]==0xe9&&second[0]==0xe9,
        "queued enable maps suspended peer into the first trampoline");
    writes=context_writes;
    require(MTH_QueueDisableHook(MTH_ALL_HOOKS)==MTH_OK,"queue disable for both hooks");
    require(MTH_ApplyQueued()==MTH_OK,"apply queued all-hook disable");
    require(peer_ip==(DWORD_PTR)(ULONG_PTR)(first+2)&&context_writes==writes+1&&
        first[0]==0x90&&second[0]==0x90,
        "queued all-hook disable returns peer to original target");
    peer_ip=(DWORD_PTR)(ULONG_PTR)(second+2);writes=context_writes;
    require(MTH_EnableHook(MTH_ALL_HOOKS)==MTH_OK,"enable all existing hooks");
    require(peer_ip==(DWORD_PTR)(ULONG_PTR)((unsigned char*)second_trampoline+2)&&
        context_writes==writes+1,"all-hook enable relocates the second target IP");
    writes=context_writes;
    require(MTH_DisableHook(MTH_ALL_HOOKS)==MTH_OK,"disable all existing hooks");
    require(peer_ip==(DWORD_PTR)(ULONG_PTR)(second+2)&&context_writes==writes+1&&
        first[0]==0x90&&second[0]==0x90,
        "all-hook disable restores second IP and both targets");
    require(!HasRetainedThreadOwnership(),"queued and all-hook transitions drain thread owners");
    require(MTH_RemoveHook(first)==MTH_OK&&MTH_RemoveHook(second)==MTH_OK,
        "remove both disabled hooks without duplicate relocation");
    require(VirtualFree(memory,0,MEM_RELEASE),"release both hook fixture targets");
    peer_ip=0;
}
int inherited_failure_suite(void) {
    FROZEN_THREADS threads;
    HANDLE heap;
    require(MTH_Initialize()==MTH_OK,"initialize actual engine");heap=g_hHeap;
    require(Freeze(&threads,ALL_HOOKS_POS,ACTION_APPLY_QUEUED)==MTH_OK,"Nt enumeration and peer preparation");
    require(enumeration==4&&threads.size==1&&threads.pItems[0].suspended,"duplicated peer owned and suspended; second coverage scan completed");
    fail_resume=TRUE;
    require(Unfreeze(&threads)==MTH_ERROR_MEMORY_PROTECT&&HasRetainedThreadOwnership(),"failed resume retains ownership");
    require(closes==0&&g_retainedThreads.pItems[0].suspended,"suspended handle cannot be closed");
    require(MTH_Uninitialize()==MTH_ERROR_MEMORY_PROTECT&&g_hHeap==heap,"engine heap survives incomplete resume");
    fail_resume=FALSE;fail_close=TRUE;
    require(!RetryRetainedThreadOwnership()&&!g_retainedThreads.pItems[0].suspended,"successful resume retained only for failed close");
    {int count=resumes;require(!RetryRetainedThreadOwnership()&&resumes==count,"retry does not resume twice");}
    fail_close=FALSE;fail_heap=TRUE;
    require(!RetryRetainedThreadOwnership()&&g_retainedThreads.pItems[0].handle==NULL,"array owner survives heap release failure");
    fail_heap=FALSE;
    require(RetryRetainedThreadOwnership()&&!HasRetainedThreadOwnership(),"retry releases final backing allocation");
    fail_cursor=TRUE;
    require(Freeze(&threads,ALL_HOOKS_POS,ACTION_ENABLE)==MTH_ERROR_MEMORY_PROTECT&&g_emergencyThread.handle==cursor_handle,"failed enumeration cursor close is retained");
    fail_cursor=FALSE;require(RetryRetainedThreadOwnership()&&!HasRetainedThreadOwnership(),"cursor owner retries cleanly");
    fail_array=fail_close=fail_cursor=TRUE;
    require(Freeze(&threads,ALL_HOOKS_POS,ACTION_ENABLE)==MTH_ERROR_MEMORY_PROTECT,"allocation plus two close failures defer cleanup");
    require(g_emergencyThread.handle==peer_handle&&g_emergencyNextThread.handle==cursor_handle,"both unclosed physical handles remain owned after append failure");
    reset_faults();require(RetryRetainedThreadOwnership()&&!HasRetainedThreadOwnership(),"both emergency owners retry cleanly");
    unavailable=TRUE;
    require(Freeze(&threads,ALL_HOOKS_POS,ACTION_ENABLE)==MTH_UNKNOWN,"missing Nt API fails closed without Toolhelp fallback");
    unavailable=FALSE;fail_context=TRUE;
    require(Freeze(&threads,ALL_HOOKS_POS,ACTION_ENABLE)==MTH_ERROR_MEMORY_PROTECT,"unresolved live thread context rejects patching");
    require(!HasRetainedThreadOwnership(),"failed preparation resumes and closes peers");
    fail_context=FALSE;fail_suspend=TRUE;
    require(Freeze(&threads,ALL_HOOKS_POS,ACTION_ENABLE)==MTH_ERROR_MEMORY_PROTECT,"failed live peer suspension rejects patching");
    reset_faults();single_hook_ip_relocation();
    reset_faults();queued_and_all_hook_ip_relocation();
    require(MTH_Uninitialize()==MTH_OK&&g_hHeap==NULL,"engine releases only after successful cleanup");
    printf("PASS: %d actual SAFE-FREEZE failure and retry checks\n",checks);return 0;
}

static void public_mutation_retry_barriers(void) {
    unsigned fault;
    for (fault = 0; fault != 3; ++fault) {
        FROZEN_THREADS threads;
        unsigned char* memory;
        LPVOID original = NULL;
        LPVOID untouched = (LPVOID)(ULONG_PTR)0x1234;
        UINT pos;
        require(MTH_Initialize() == MTH_OK, "initialize public mutation recovery case");
        memory = VirtualAlloc(NULL, 128, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        require(memory != NULL, "allocate two public mutation targets");
        memset(memory, 0x90, 128);
        memory[16] = memory[32] = memory[80] = memory[96] = 0xc3;
        require(MTH_CreateHook(memory, memory + 32, &original) == MTH_OK,
                "create disabled hook before mutation recovery case");
        pos = FindHookEntry(memory);
        require(Freeze(&threads, ALL_HOOKS_POS, ACTION_ENABLE) == MTH_OK,
                "acquire exact owner before public mutation failure");
        fail_resume = fault == 0;
        fail_close = fault == 1;
        fail_heap = fault == 2;
        require(Unfreeze(&threads) == MTH_ERROR_MEMORY_PROTECT && HasRetainedThreadOwnership(),
                "resume, close or heap failure retains its exact owner");
        require(MTH_CreateHook(memory + 64, memory + 96, &untouched) == MTH_ERROR_MEMORY_PROTECT &&
                untouched == (LPVOID)(ULONG_PTR)0x1234 && g_hooks.size == 1 &&
                FindHookEntry(memory + 64) == INVALID_HOOK_POS,
                "new hook creation cannot bypass retained cleanup");
        require(MTH_QueueEnableHook(memory) == MTH_ERROR_MEMORY_PROTECT &&
                !g_hooks.pItems[pos].queueEnable && !g_hooks.pItems[pos].isEnabled,
                "queue mutation cannot bypass retained cleanup");
        require(MTH_DisableHook(memory) == MTH_ERROR_MEMORY_PROTECT &&
                !g_hooks.pItems[pos].isEnabled,
                "already-disabled mutation must report pending cleanup");
        require(MTH_ApplyQueued() == MTH_ERROR_MEMORY_PROTECT && HasRetainedThreadOwnership(),
                "empty apply preserves resume, close and heap owners");
        require(MTH_RemoveHook(memory) == MTH_ERROR_MEMORY_PROTECT &&
                FindHookEntry(memory) == pos && g_hooks.pItems[pos].pTrampoline == original,
                "disabled removal preserves the same trampoline until cleanup succeeds");
        reset_faults();
        require(MTH_QueueEnableHook(memory) == MTH_OK && !HasRetainedThreadOwnership() &&
                g_hooks.pItems[pos].queueEnable,
                "public queue retry releases the old owner before changing pending intent");
        require(MTH_QueueDisableHook(memory) == MTH_OK, "cancel recovered queue without patching");
        require(MTH_CreateHook(memory + 64, memory + 96, &untouched) == MTH_OK &&
                untouched != NULL && untouched != (LPVOID)(ULONG_PTR)0x1234,
                "create succeeds with an actual trampoline after cleanup recovery");
        require(MTH_RemoveHook(memory) == MTH_OK && MTH_RemoveHook(memory + 64) == MTH_OK,
                "remove recovered disabled hooks exactly once");
        require(MTH_Uninitialize() == MTH_OK && g_hHeap == NULL,
                "uninitialize recovered mutation case");
        require(VirtualFree(memory, 0, MEM_RELEASE), "release recovered target allocation");
    }
}

int main(void) {
    FROZEN_THREADS threads;
    unsigned char *target;
    LPVOID trampoline=NULL;
    HANDLE heap;
    UINT capacity;
    inherited_failure_suite();
    require(MTH_Initialize()==MTH_OK,"reinitialize after inherited suite");
    heap=g_hHeap;
    fail_enumeration=TRUE;
    require(Freeze(&threads,ALL_HOOKS_POS,ACTION_ENABLE)==MTH_UNKNOWN&&!HasRetainedThreadOwnership(),"enumeration API error classification");
    fail_enumeration=FALSE;return_second_cursor=fail_cursor=fail_second_cursor=fail_close=TRUE;
    require(Freeze(&threads,ALL_HOOKS_POS,ACTION_ENABLE)==MTH_ERROR_MEMORY_PROTECT,"failed cursor close retains new next cursor and peer duplicate");
    require(g_emergencyThread.handle==cursor_handle&&g_emergencyNextThread.handle==second_cursor_handle&&g_retainedThreads.pItems[0].handle==peer_handle,"three distinct physical owners survive combined cleanup failures");
    return_second_cursor=fail_cursor=fail_second_cursor=FALSE;
    require(!RetryRetainedThreadOwnership()&&g_emergencyThread.handle==NULL&&g_emergencyNextThread.handle==NULL&&g_retainedThreads.pItems!=NULL,"cleanup releases both emergency owners but preserves failed duplicate close");
    fail_close=FALSE;require(RetryRetainedThreadOwnership()&&!HasRetainedThreadOwnership(),"release final duplicate owner after emergency recovery");
    fail_duplicate=TRUE;
    require(Freeze(&threads,ALL_HOOKS_POS,ACTION_ENABLE)==MTH_UNKNOWN&&!HasRetainedThreadOwnership(),"duplicate failure closes cursor without fallback");
    fail_duplicate=FALSE;include_current=TRUE;
    require(Freeze(&threads,ALL_HOOKS_POS,ACTION_ENABLE)==MTH_OK&&threads.size==0,"exclude current thread without suspension");
    require(Unfreeze(&threads)==MTH_OK,"empty freeze cleanup");include_current=FALSE;
    peer_dead=TRUE;fail_suspend=TRUE;
    require(Freeze(&threads,ALL_HOOKS_POS,ACTION_ENABLE)==MTH_OK,"terminated peer suspend failure is resolved");
    require(Unfreeze(&threads)==MTH_OK,"terminated peer handle closes");
    fail_suspend=FALSE;fail_context=TRUE;
    {int before=resumes;
    require(Freeze(&threads,ALL_HOOKS_POS,ACTION_ENABLE)==MTH_OK,"terminated peer get-context failure is resolved");
    require(Unfreeze(&threads)==MTH_OK&&resumes==before,"terminated peer retires without spurious resume");}
    fail_context=FALSE;fail_suspend=TRUE;
    peer_dead=FALSE;peer_invalid=TRUE;
    require(Freeze(&threads,ALL_HOOKS_POS,ACTION_ENABLE)==MTH_OK,"invalid peer handle is resolved");
    require(Unfreeze(&threads)==MTH_OK,"invalid peer cleanup resolves");
    peer_invalid=fail_suspend=FALSE;
    memset(&threads,0,sizeof threads);
    require(AppendThreadHandle(&threads,peer_handle),"initial thread allocation");
    capacity=threads.capacity;threads.size=capacity;fail_reallocate=TRUE;
    require(!AppendThreadHandle(&threads,peer_handle)&&threads.capacity==capacity&&threads.pItems[0].handle==peer_handle,"failed growth preserves prior array owner");
    threads.size=1;fail_reallocate=FALSE;require(Unfreeze(&threads)==MTH_OK,"release retained original allocation");
    target=(unsigned char*)VirtualAlloc(NULL,64,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    require(target!=NULL,"allocate disabled-removal owner fixture");memset(target,0x90,64);target[16]=target[32]=0xc3;
    require(MTH_CreateHook(target,target+32,&trampoline)==MTH_OK,"create disabled hook before retained cleanup");
    require(Freeze(&threads,ALL_HOOKS_POS,ACTION_ENABLE)==MTH_OK,"own peer before injected cleanup fault");
    fail_resume=TRUE;require(Unfreeze(&threads)==MTH_ERROR_MEMORY_PROTECT,"retain failed resume");
    require(MTH_ApplyQueued()==MTH_ERROR_MEMORY_PROTECT&&HasRetainedThreadOwnership(),"no-op apply must not hide unresolved owner");
    require(MTH_RemoveHook(target+48)==MTH_ERROR_MEMORY_PROTECT&&FindHookEntry(target)!=INVALID_HOOK_POS,"disabled removal cannot retire trampoline under unresolved ownership");
    require(MTH_Uninitialize()==MTH_ERROR_MEMORY_PROTECT&&g_hHeap==heap,"incomplete cleanup keeps same engine heap");
    fail_resume=FALSE;require(MTH_ApplyQueued()==MTH_OK&&!HasRetainedThreadOwnership(),"no-op apply retries retained cleanup");
    require(MTH_RemoveHook(target)==MTH_OK,"remove after exact owner recovery");
    require(VirtualFree(target,0,MEM_RELEASE),"release target fixture");
    require(MTH_Uninitialize()==MTH_OK,"final teardown");
    public_mutation_retry_barriers();
    printf("PASS: %d inherited and extended injected-failure checks (synthetic peers)\n",checks);
    return 0;
}
