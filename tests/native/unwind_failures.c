// SPDX-License-Identifier: GPL-3.0-only
// Genuine Windows runtime-function APIs with projected peer scheduling and
// deterministic registration, deletion, flush, heap and memory-release faults.
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <MithrilHook.h>

static unsigned checks, suspended, suspends, adds, deletes, frees;
static BOOL fail_add, fail_delete, fail_free, fail_flush;
static unsigned fail_delete_after, fail_free_call;
static SIZE_T fail_heap_size;
static LPVOID last_buffer;
static DWORD_PTR peer_stack[4];
static HANDLE cursor=(HANDLE)(ULONG_PTR)0x6a01,peer=(HANDLE)(ULONG_PTR)0x6a02;
static void require(BOOL ok,const char *why)
{
    ++checks;
    if(!ok){fprintf(stderr,"FAIL: %s\n",why);ExitProcess(1);}
}
static LONG NTAPI next_peer(HANDLE process,HANDLE previous,ACCESS_MASK access,ULONG attributes,ULONG flags,PHANDLE next)
{
    (void)process;(void)access;(void)attributes;(void)flags;
    *next=previous?NULL:cursor;return *next?0:(LONG)0x8000001aL;
}
static FARPROC WINAPI lookup(HMODULE module,LPCSTR name)
{return !strcmp(name,"NtGetNextThread")?(FARPROC)next_peer:GetProcAddress(module,name);}
static DWORD WINAPI thread_id(HANDLE h)
{return h==cursor||h==peer?GetCurrentThreadId()+1:GetThreadId(h);}
static BOOL WINAPI duplicate(HANDLE a,HANDLE h,HANDLE b,LPHANDLE out,DWORD access,BOOL inherit,DWORD flags)
{if(h==cursor){*out=peer;return TRUE;}return DuplicateHandle(a,h,b,out,access,inherit,flags);}
static DWORD WINAPI suspend_peer(HANDLE h)
{if(h==peer){++suspended;++suspends;return 0;}return SuspendThread(h);}
static DWORD WINAPI resume_peer(HANDLE h)
{if(h==peer){require(suspended==1,"resume exactly the owned projected suspension");--suspended;return 1;}return ResumeThread(h);}
static BOOL WINAPI close_peer(HANDLE h)
{return h==cursor||h==peer?TRUE:CloseHandle(h);}
static BOOL WINAPI exit_code(HANDLE h,LPDWORD code)
{if(h==cursor||h==peer){*code=STILL_ACTIVE;return TRUE;}return GetExitCodeThread(h,code);}
static BOOL WINAPI context_peer(HANDLE h,LPCONTEXT context)
{
    if(h==peer){DWORD flags=context->ContextFlags;memset(context,0,sizeof(*context));context->ContextFlags=flags;
        context->Rsp=(DWORD64)(ULONG_PTR)peer_stack;return TRUE;}
    return GetThreadContext(h,context);
}
static BOOL WINAPI set_context_peer(HANDLE h,const CONTEXT *context)
{if(h==peer)return TRUE;return SetThreadContext(h,context);}
static SIZE_T WINAPI query(LPCVOID address,PMEMORY_BASIC_INFORMATION out,SIZE_T size)
{
    ULONG_PTR at=(ULONG_PTR)address,start=(ULONG_PTR)peer_stack,end=start+sizeof(peer_stack);
    if(at>=start&&at<=end){memset(out,0,sizeof(*out));out->BaseAddress=(LPVOID)(at==end?end:start);
        out->AllocationBase=out->BaseAddress;out->RegionSize=at==end?8:sizeof(peer_stack);
        out->State=MEM_COMMIT;out->Protect=PAGE_READWRITE;return sizeof(*out);}
    return VirtualQuery(address,out,size);
}
static BOOLEAN NTAPI add_table(PRUNTIME_FUNCTION functions,DWORD count,DWORD64 base)
{
    require(suspended==0,"runtime-function registration never runs while owned peers are suspended");
    ++adds;last_buffer=(LPVOID)(ULONG_PTR)base;
    return fail_add?FALSE:RtlAddFunctionTable(functions,count,base);
}
static BOOLEAN NTAPI delete_table(PRUNTIME_FUNCTION functions)
{
    require(suspended==0,"runtime-function deletion never runs while owned peers are suspended");
    ++deletes;
    return fail_delete||(fail_delete_after&&deletes>=fail_delete_after)?FALSE:RtlDeleteFunctionTable(functions);
}
static BOOL WINAPI free_memory(LPVOID address,SIZE_T size,DWORD mode)
{
    ++frees;
    if(fail_free||(fail_free_call&&frees==fail_free_call)){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    return VirtualFree(address,size,mode);
}
static BOOL WINAPI flush(HANDLE process,LPCVOID address,SIZE_T size)
{return fail_flush?FALSE:FlushInstructionCache(process,address,size);}
static LPVOID WINAPI heap_alloc(HANDLE heap,DWORD flags,SIZE_T size)
{return fail_heap_size&&size==fail_heap_size?NULL:HeapAlloc(heap,flags,size);}

#define GetProcAddress lookup
#define GetThreadId thread_id
#define DuplicateHandle duplicate
#define SuspendThread suspend_peer
#define ResumeThread resume_peer
#define CloseHandle close_peer
#define GetExitCodeThread exit_code
#define GetThreadContext context_peer
#define SetThreadContext set_context_peer
#define VirtualQuery query
#define RtlAddFunctionTable add_table
#define RtlDeleteFunctionTable delete_table
#define VirtualFree free_memory
#define FlushInstructionCache flush
#define HeapAlloc heap_alloc
#include "buffer.c"
#include "hook.c"
#undef RtlAddFunctionTable
#undef RtlDeleteFunctionTable
#undef VirtualFree
#undef FlushInstructionCache

static BYTE *code;
static RUNTIME_FUNCTION source_functions[32];
static const BYTE instructions[]={0x53,0x48,0x83,0xec,0x20,0x90,0xb8,7,0,0,0,0x48,0x83,0xc4,0x20,0x5b,0xc3};
static const BYTE info[]={1,5,2,0,5,0x32,1,0x30};
static void setup(unsigned count)
{
    unsigned i;
    suspended=suspends=adds=deletes=frees=0;
    fail_add=fail_delete=fail_free=fail_flush=FALSE;
    fail_delete_after=fail_free_call=0;fail_heap_size=0;last_buffer=NULL;
    memset(peer_stack,0,sizeof(peer_stack));
    code=VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    require(code!=NULL&&count<=32,"allocate bounded source-function fixture");memset(code,0x90,8192);
    for(i=0;i<count;++i)
    {
        memcpy(code+i*64,instructions,sizeof(instructions));memcpy(code+4096+i*16,info,sizeof(info));
        source_functions[i].BeginAddress=i*64;source_functions[i].EndAddress=i*64+32;
        source_functions[i].UnwindData=4096+i*16;
    }
    code[2048]=0xc3;
    require(RtlAddFunctionTable(source_functions,count,(DWORD64)(ULONG_PTR)code),"register held source functions");
    require(FlushInstructionCache(GetCurrentProcess(),code,8192),"flush source instructions");
    require(MTH_Initialize()==MTH_OK,"initialize unwind-failure engine");
}
static LPVOID create(unsigned index)
{
    LPVOID original=NULL;
    require(MTH_CreateHook(code+index*64,code+2048,&original)==MTH_OK&&original!=NULL,"publish registered trampoline for failure case");
    require(MTH_BUFFER_UNWIND(original)->registered,"published trampoline owns registered metadata");
    return original;
}
static BOOL registered(LPVOID original)
{
    DWORD64 base;
    return RtlLookupFunctionEntry((DWORD64)(ULONG_PTR)((BYTE*)original+5),&base,NULL)!=NULL;
}
static void finish(void)
{
    fail_add=fail_delete=fail_free=fail_flush=FALSE;fail_delete_after=fail_free_call=0;fail_heap_size=0;
    require(MTH_Uninitialize()==MTH_OK&&g_hHeap==NULL&&g_pMemoryBlocks==NULL,"complete engine heap, block and table retirement");
    require(suspended==0&&!HasRetainedThreadOwnership()&&!MthInternal_HasPendingBufferUnwind(),"drain all peer and metadata owners");
    require(RtlDeleteFunctionTable(source_functions),"unregister source owner after engine teardown");
    require(VirtualFree(code,0,MEM_RELEASE),"free source allocation last");code=NULL;
}
static void initial_registration_failure(void)
{
    LPVOID original=(LPVOID)(ULONG_PTR)0x1234;setup(1);fail_add=TRUE;
    require(MTH_CreateHook(code,code+2048,&original)==MTH_ERROR_MEMORY_PROTECT&&original==(LPVOID)(ULONG_PTR)0x1234,
        "failed initial registration never publishes an original pointer");
    require(g_hooks.size==0&&g_pMemoryBlocks==NULL&&!g_retainedBuffer,"failed initial registration releases its unpublished allocation");
    finish();
}
static void deletion_failure(void)
{
    LPVOID original;setup(1);original=create(0);fail_delete=TRUE;
    require(MTH_RemoveHook(code)==MTH_ERROR_MEMORY_PROTECT&&registered(original)&&frees==0,
        "failed table deletion retains both registered metadata and executable storage");
    require(FindHookEntry(code)!=INVALID_HOOK_POS&&suspended==0,"failed deletion keeps the exact disabled hook owner after peer release");
    fail_delete=FALSE;require(MTH_RemoveHook(code)==MTH_OK&&!registered(original),"retry deletes table before releasing code");finish();
}
static void free_failure(BOOL repairFails)
{
    LPVOID original;unsigned before;setup(1);original=create(0);fail_free=TRUE;fail_add=repairFails;
    require(MTH_RemoveHook(code)==MTH_ERROR_MEMORY_PROTECT,"memory-release failure retains the disabled hook owner");
    require(suspended==0&&FindHookEntry(code)!=INVALID_HOOK_POS,"retained memory-release owner has no suspended registry lock holders");
    if(repairFails)
    {
        before=suspends;
        require(!registered(original)&&MthInternal_HasPendingBufferUnwind(),"failed registration rollback preserves the exact pending table owner");
        require(MTH_ApplyQueued()==MTH_ERROR_MEMORY_PROTECT&&suspends==before,"pending metadata recovery blocks mutation before acquiring peers");
        fail_add=FALSE;require(MTH_ApplyQueued()==MTH_OK&&registered(original),"metadata recovery restores registry ownership before new mutation");
    }
    else
        require(registered(original)&&!MthInternal_HasPendingBufferUnwind(),"failed memory release restores published unwind metadata");
    fail_free=FALSE;require(MTH_RemoveHook(code)==MTH_OK&&!registered(original),"release retry unregisters and frees the same owner");finish();
}
static void unpublished_failure(BOOL heap)
{
    LPVOID original=(LPVOID)(ULONG_PTR)0x1234;setup(1);fail_delete=TRUE;
    if(heap)fail_heap_size=INITIAL_HOOK_CAPACITY*sizeof(HOOK_ENTRY);else fail_flush=TRUE;
    require(MTH_CreateHook(code,code+2048,&original)==MTH_ERROR_MEMORY_PROTECT&&original==(LPVOID)(ULONG_PTR)0x1234,
        "post-registration publication failure preserves caller output");
    require(g_hooks.size==0&&g_retainedBuffer==last_buffer&&registered(last_buffer),"failed unpublished cleanup retains its registered buffer owner");
    require(MTH_ApplyQueued()==MTH_ERROR_MEMORY_PROTECT,"unpublished table cleanup failure blocks no-op mutation");
    fail_delete=fail_flush=FALSE;fail_heap_size=0;
    require(MTH_ApplyQueued()==MTH_OK&&g_retainedBuffer==NULL&&g_pMemoryBlocks==NULL,"retry retires the exact unpublished table and storage");finish();
}
static void partial_table_teardown(void)
{
    HANDLE heap;setup(2);create(0);create(1);heap=g_hHeap;
    fail_delete_after=2;fail_add=TRUE;
    require(MTH_Uninitialize()==MTH_ERROR_MEMORY_PROTECT&&g_hHeap==heap&&g_shutdownPending,
        "partial table deletion retains shutdown-only heap and remaining tables");
    require(deletes==2&&frees==0&&MthInternal_HasPendingBufferUnwind()&&suspended==0,
        "failed partial-table rollback remains discoverable without freeing storage");
    require(MTH_QueueEnableHook(code)==MTH_ERROR_MEMORY_PROTECT,"partial table teardown rejects fresh activation");
    fail_add=FALSE;fail_delete_after=0;finish();
}
static void partial_block_teardown(void)
{
    LPVOID originals[18];unsigned i;setup(18);
    for(i=0;i<18;++i)originals[i]=create(i);
    fail_free_call=2;
    require(MTH_Uninitialize()==MTH_ERROR_MEMORY_PROTECT&&frees==2&&g_pMemoryBlocks!=NULL&&g_pMemoryBlocks->pNext==NULL,
        "partial block release retains only the remaining registered block");
    require(!MthInternal_HasPendingBufferUnwind(),"remaining block table rollback completes before returning failure");
    fail_free_call=0;finish();
    for(i=0;i<18;++i)require(!registered(originals[i]),"final teardown removes every generated table");
}
int main(void)
{
    initial_registration_failure();deletion_failure();free_failure(FALSE);free_failure(TRUE);
    unpublished_failure(FALSE);unpublished_failure(TRUE);partial_table_teardown();partial_block_teardown();
    printf("PASS: %u native registry/retirement failure checks with projected peers; no registry call during owned suspension\n",checks);
    return 0;
}
