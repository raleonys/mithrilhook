// SPDX-License-Identifier: BSD-2-Clause AND GPL-3.0-only

/* Actual strict engine with deterministic failure boundaries. Targets and
 * projected peers are never executed. Real page protection is checked below. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <MithrilHook.h>

#if defined(_M_X64) || defined(__x86_64__)
#define PEER_IP(c) ((c)->Rip)
#define PEER_SP(c) ((c)->Rsp)
#define PEER_REGISTER(c) ((c)->Rax)
#else
#define PEER_IP(c) ((c)->Eip)
#define PEER_SP(c) ((c)->Esp)
#define PEER_REGISTER(c) ((c)->Eax)
#endif

static BOOL fail_restore, fail_write_protect, fail_flush, fail_free, fail_destroy;
static BOOL two_peers,fail_second_context,fail_stack_read,short_stack_read;
static BOOL late_peer;
static unsigned scans, context_reads, fail_context_read_after;
static DWORD_PTR fail_context_destination;
static unsigned fail_write_call,write_calls;
static unsigned fail_free_after,free_calls;
static unsigned checks, enumerations, resumes;
static DWORD_PTR peer_ip, peer_register;
static DWORD_PTR peer_stack[160];
static SIZE_T peer_stack_offset, peer_stack_split;
static unsigned stack_reads, fail_stack_read_after, short_stack_read_after;
static BOOL fail_stack_query, oversized_stack_region;
static unsigned bad_stack_region;
static HANDLE cursor = (HANDLE)(ULONG_PTR)0x6781;
static HANDLE peer = (HANDLE)(ULONG_PTR)0x6782;
static HANDLE cursor2 = (HANDLE)(ULONG_PTR)0x6783;
static HANDLE peer2 = (HANDLE)(ULONG_PTR)0x6784;
static void require(BOOL ok, const char* why) {
    ++checks;
    if (!ok) { fprintf(stderr,"FAIL: %s\n",why); exit(1); }
}
static LONG NTAPI next_peer(HANDLE process,HANDLE previous,ACCESS_MASK access,ULONG attributes,ULONG flags,PHANDLE next) {
    (void)process;(void)access;(void)attributes;(void)flags;++enumerations;
    if (!previous) ++scans;
    *next = !previous ? cursor : (two_peers || (late_peer && scans >= 2)) && previous==cursor ? cursor2 : NULL;
    return *next ? 0 : (LONG)0x8000001AL;
}
static FARPROC WINAPI lookup(HMODULE module,LPCSTR name) {
    return !strcmp(name,"NtGetNextThread") ? (FARPROC)next_peer : GetProcAddress(module,name);
}
static DWORD WINAPI thread_id(HANDLE h) {
    if(h==cursor || h==peer)return GetCurrentThreadId()+1;
    if(h==cursor2 || h==peer2)return GetCurrentThreadId()+2;
    return GetThreadId(h);
}
static BOOL WINAPI duplicate(HANDLE a,HANDLE h,HANDLE b,LPHANDLE out,DWORD access,BOOL inherit,DWORD flags) {
    if(h==cursor || h==cursor2){*out=h==cursor?peer:peer2;return TRUE;}return DuplicateHandle(a,h,b,out,access,inherit,flags);
}
static DWORD WINAPI suspend_peer(HANDLE h) { return h==peer || h==peer2 ? 0 : SuspendThread(h); }
static DWORD WINAPI resume_peer(HANDLE h) { if(h==peer || h==peer2){++resumes;return 1;}return ResumeThread(h); }
static BOOL WINAPI close_peer(HANDLE h) { return h==peer || h==cursor || h==peer2 || h==cursor2 ? TRUE : CloseHandle(h); }
static BOOL WINAPI exit_code(HANDLE h,LPDWORD out) { if(h==peer || h==peer2 || h==cursor || h==cursor2){*out=STILL_ACTIVE;return TRUE;}return GetExitCodeThread(h,out); }
static BOOL WINAPI context_peer(HANDLE h,LPCONTEXT out) {
    if(h==peer || h==peer2){DWORD flags=out->ContextFlags;
        ++context_reads;
        if(fail_context_read_after && context_reads>fail_context_read_after){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
        if(h==peer2 && fail_second_context){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
        memset(out,0,sizeof(*out));out->ContextFlags=flags;
        PEER_IP(out)=h==peer?peer_ip:0;PEER_REGISTER(out)=peer_register;PEER_SP(out)=(DWORD_PTR)(ULONG_PTR)((BYTE*)peer_stack+peer_stack_offset);return TRUE;}
    return GetThreadContext(h,out);
}
static BOOL WINAPI set_context_peer(HANDLE h,const CONTEXT* in) {
    if(h==peer || h==peer2){
        if(fail_context_destination && PEER_IP(in)==fail_context_destination){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
        if(h==peer)peer_ip=PEER_IP(in);return TRUE;}return SetThreadContext(h,in);
}
static SIZE_T WINAPI query(LPCVOID address,PMEMORY_BASIC_INFORMATION out,SIZE_T size) {
    ULONG_PTR at=(ULONG_PTR)address,start=(ULONG_PTR)peer_stack,end=start+sizeof(peer_stack);
    if(at>=start && at<=end){
        BOOL second=peer_stack_split && at>=start+peer_stack_split && at<end;
        ULONG_PTR base=at==end?end:second?start+peer_stack_split:start;
        if(fail_stack_query && second)return 0;
        memset(out,0,sizeof(*out));out->BaseAddress=(LPVOID)base;
        out->AllocationBase=(LPVOID)(at==end?end:start);
        out->RegionSize=at==end?8:second?end-base:peer_stack_split?peer_stack_split:sizeof(peer_stack);
        if(oversized_stack_region)out->RegionSize=64*1024*1024+1;
        out->State=second && bad_stack_region==3?MEM_RESERVE:MEM_COMMIT;
        out->Protect=second && bad_stack_region==1?PAGE_READWRITE|PAGE_GUARD:
            second && bad_stack_region==2?PAGE_NOACCESS:PAGE_READWRITE;
        return sizeof(*out);}
    return VirtualQuery(address,out,size);
}
static BOOL WINAPI protect(LPVOID p,SIZE_T n,DWORD mode,PDWORD old) {
    if(mode==PAGE_EXECUTE_READWRITE)++write_calls;
    if((fail_restore && mode!=PAGE_EXECUTE_READWRITE) || (fail_write_protect && mode==PAGE_EXECUTE_READWRITE) ||
        (fail_write_call && write_calls==fail_write_call && mode==PAGE_EXECUTE_READWRITE)){
        SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    return VirtualProtect(p,n,mode,old);
}
static BOOL WINAPI read_stack(HANDLE process,LPCVOID p,LPVOID out,SIZE_T n,SIZE_T* copied) {
    if((ULONG_PTR)p>=(ULONG_PTR)peer_stack && (ULONG_PTR)p<(ULONG_PTR)peer_stack+sizeof(peer_stack)){
        ++stack_reads;
        if(fail_stack_read || (fail_stack_read_after && stack_reads>fail_stack_read_after)){*copied=0;return FALSE;}
        if(short_stack_read || (short_stack_read_after && stack_reads>short_stack_read_after)){memcpy(out,p,n);*copied=n-1;return TRUE;}}
    return ReadProcessMemory(process,p,out,n,copied);
}
static BOOL WINAPI flush(HANDLE process,LPCVOID p,SIZE_T n) {
    if(fail_flush){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}return FlushInstructionCache(process,p,n);
}
static BOOL WINAPI release(LPVOID p,SIZE_T n,DWORD mode) {
    ++free_calls;
    if(fail_free || (fail_free_after && free_calls>fail_free_after)){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    return VirtualFree(p,n,mode);
}
static BOOL WINAPI destroy(HANDLE h) {
    if(fail_destroy){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}return HeapDestroy(h);
}
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
#define VirtualProtect protect
#define FlushInstructionCache flush
#define VirtualFree release
#define HeapDestroy destroy
#define ReadProcessMemory read_stack
#ifndef MTH_TEST_BUFFER_SOURCE
#define MTH_TEST_BUFFER_SOURCE "buffer.c"
#endif
#include MTH_TEST_BUFFER_SOURCE
#ifndef MTH_TEST_ENGINE_SOURCE
#define MTH_TEST_ENGINE_SOURCE "hook.c"
#endif
#include MTH_TEST_ENGINE_SOURCE
#undef VirtualProtect
#undef VirtualFree

static unsigned char* target;
static void setup(void) {
    DWORD old;
    fail_restore=fail_write_protect=fail_flush=fail_free=fail_destroy=FALSE;
    two_peers=fail_second_context=fail_stack_read=short_stack_read=FALSE;
    late_peer=FALSE;scans=context_reads=fail_context_read_after=0;fail_context_destination=0;
    fail_write_call=write_calls=0;
    fail_free_after=free_calls=0;
    peer_stack_offset=peer_stack_split=0;stack_reads=fail_stack_read_after=short_stack_read_after=0;
    fail_stack_query=oversized_stack_region=FALSE;bad_stack_region=0;
    peer_ip=peer_register=0;memset(peer_stack,0,sizeof peer_stack);
    require(MTH_Initialize()==MTH_OK,"initialize completion fixture");
    target=(unsigned char*)VirtualAlloc(NULL,8192,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    require(target!=NULL,"allocate two-page target");memset(target,0x90,8192);target[32]=target[96]=0xc3;
    require(VirtualProtect(target,8192,PAGE_EXECUTE_READ,&old),"protect target RX");
}
static LPVOID create_at(unsigned offset) {
    LPVOID original=NULL;
    require(MTH_CreateHook(target+offset,target+96,&original)==MTH_OK && original!=NULL,"create completion hook");
    return original;
}
static void finish(void) {
    require(MTH_Uninitialize()==MTH_OK,"completion fixture shutdown");
    require(VirtualFree(target,0,MEM_RELEASE),"release completion target");target=NULL;
}
static void completion_retry(BOOL cache) {
    LPVOID original;unsigned before;
    setup();original=create_at(0);(void)original;
    fail_flush=cache;fail_restore=!cache;
    before=resumes;
    require(MTH_EnableHook(target)==MTH_ERROR_MEMORY_PROTECT,"post-write completion failure must not report success");
    require(resumes==before,"incomplete instruction stream cannot resume owned peers");
    before=enumerations;
    require(MTH_ApplyQueued()==MTH_ERROR_MEMORY_PROTECT && enumerations==before,"pending completion blocks even no-op apply without acquiring peers");
    require(MTH_EnableHook(target)==MTH_ERROR_MEMORY_PROTECT,"already-enabled request cannot hide incomplete completion");
    require(MTH_QueueDisableHook(target)==MTH_ERROR_MEMORY_PROTECT,"pending completion preserves queued intent");
    require(MTH_RemoveHook(target)==MTH_ERROR_MEMORY_PROTECT,"pending completion retains hook storage");
    fail_flush=fail_restore=FALSE;
    require(MTH_DisableHook(target)==MTH_OK,"retry completes prior write before disabling");
    require(target[0]==0x90,"retry restores exact target bytes");finish();
}
static void prewrite_retirement(void) {
    LPVOID original;setup();original=create_at(0);peer_ip=(DWORD_PTR)(ULONG_PTR)target;
    fail_write_protect=TRUE;
    require(MTH_EnableHook(target)==MTH_ERROR_MEMORY_PROTECT && target[0]==0x90,"pre-write failure leaves target unchanged");
    require(peer_ip==(DWORD_PTR)(ULONG_PTR)target,"pre-write refusal restores the original peer IP");
    fail_write_protect=FALSE;
    peer_ip=(DWORD_PTR)(ULONG_PTR)original; /* Independently exercise retirement of an occupied buffer. */
    require(MTH_RemoveHook(target)==MTH_ERROR_MEMORY_PROTECT,"disabled removal retains trampoline occupied by projected peer");
    require(MTH_Uninitialize()==MTH_ERROR_MEMORY_PROTECT,"uninitialize retains trampoline occupied by projected peer");
    peer_ip=0;peer_stack[0]=(DWORD_PTR)(ULONG_PTR)original;
    require(MTH_Uninitialize()==MTH_ERROR_MEMORY_PROTECT,"trampoline return address retains allocation");
    peer_stack[0]=0;peer_register=(DWORD_PTR)(ULONG_PTR)original;
    require(MTH_Uninitialize()==MTH_ERROR_MEMORY_PROTECT,"trampoline address in register retains allocation");
    peer_register=0;finish();
}
static void release_retry(BOOL heap) {
    HANDLE owner;setup();create_at(0);owner=g_hHeap;
    fail_destroy=heap;fail_free=!heap;
    require(MTH_Uninitialize()==MTH_ERROR_MEMORY_PROTECT && g_hHeap==owner,"failed retirement keeps exact engine owner");
    require(MTH_Uninitialize()==MTH_ERROR_MEMORY_PROTECT && g_hHeap==owner,"persistent retirement failure stays retryable");
    require(MTH_EnableHook(target)==MTH_ERROR_MEMORY_PROTECT,"partial retirement prohibits mutations");
    fail_destroy=fail_free=FALSE;finish();
}
static void page_protections(void) {
    DWORD old;MEMORY_BASIC_INFORMATION first,second;setup();
    require(VirtualProtect(target+4096,4096,PAGE_EXECUTE_READWRITE,&old),"different second-page protection");
    create_at(4094);
    require(MTH_EnableHook(target+4094)==MTH_OK,"enable cross-page target");
    require(VirtualQuery(target,&first,sizeof first) && VirtualQuery(target+4096,&second,sizeof second),"query actual page protections");
    require(first.Protect==PAGE_EXECUTE_READ && second.Protect==PAGE_EXECUTE_READWRITE,"restore each page's own protection");
    require(MTH_DisableHook(target+4094)==MTH_OK,"disable cross-page target");
    require(VirtualQuery(target+4096,&second,sizeof second) && second.Protect==PAGE_EXECUTE_READWRITE,"disable preserves second-page protection");finish();
}
static void unpublished_failure(void) {
    LPVOID original=(LPVOID)(ULONG_PTR)0x1234;setup();fail_flush=fail_free=TRUE;
    require(MTH_CreateHook(target,target+96,&original)==MTH_ERROR_MEMORY_PROTECT && original==(LPVOID)(ULONG_PTR)0x1234,"failed generated-code flush never publishes original");
    require(MTH_ApplyQueued()==MTH_ERROR_MEMORY_PROTECT,"failed unpublished-buffer release retains owner");
    fail_flush=fail_free=FALSE;create_at(0);finish();
}
static void partial_batch(void) {
    LPVOID second;setup();create_at(0);second=create_at(64);
    require(MTH_QueueEnableHook(target)==MTH_OK && MTH_QueueEnableHook(target+64)==MTH_OK,"queue two-target batch");
    peer_ip=(DWORD_PTR)(ULONG_PTR)(target+64);fail_write_call=2;
    require(MTH_ApplyQueued()==MTH_ERROR_MEMORY_PROTECT && target[0]==0xe9 && target[64]==0x90,"second-target failure preserves physical partial-batch state");
    require(peer_ip==(DWORD_PTR)(ULONG_PTR)(target+64),"unwritten batch target retains its original peer IP");
    fail_write_call=0;
    require(MTH_ApplyQueued()==MTH_OK && peer_ip==(DWORD_PTR)(ULONG_PTR)second,"retry commits remaining queued enable and its peer mapping");
    require(MTH_DisableHook(MTH_ALL_HOOKS)==MTH_OK && target[0]==0x90 && target[64]==0x90,"explicit rollback restores written prefix");
    peer_ip=0;finish();
}
static void partial_preparation(void) {
    LPVOID original;setup();original=create_at(0);two_peers=fail_second_context=TRUE;peer_ip=(DWORD_PTR)(ULONG_PTR)target;
    require(MTH_EnableHook(target)==MTH_ERROR_MEMORY_PROTECT && target[0]==0x90,"later peer preparation failure rejects target mutation");
    require(peer_ip==(DWORD_PTR)(ULONG_PTR)target,"later preparation failure restores the earlier peer IP");
    fail_second_context=FALSE;
    (void)original;
    peer_ip=0;finish();
}
static void partial_disable(BOOL written) {
    LPVOID first,second;setup();first=create_at(0);second=create_at(64);
    require(MTH_EnableHook(MTH_ALL_HOOKS)==MTH_OK,"enable both targets before partial disable");
    peer_ip=(DWORD_PTR)(ULONG_PTR)(written?(BYTE*)first+1:(BYTE*)second+1);
    require(MTH_QueueDisableHook(MTH_ALL_HOOKS)==MTH_OK,"queue both disables");
    write_calls=0;fail_write_call=2;
    require(MTH_ApplyQueued()==MTH_ERROR_MEMORY_PROTECT && target[0]==0x90 && target[64]==0xe9,"disable failure preserves actual partial batch bytes");
    require(peer_ip==(DWORD_PTR)(ULONG_PTR)(written?target+1:(BYTE*)second+1),"partial disable maps peers only for physically written targets");
    require(!HasRetainedThreadOwnership(),"completed partial-batch reconciliation drains peers");
    fail_write_call=0;
    require(MTH_ApplyQueued()==MTH_OK && target[64]==0x90,"retry finishes remaining queued disable");
    require(peer_ip==(DWORD_PTR)(ULONG_PTR)(written?target+1:target+65),"retry maps the remaining disabled target");
    finish();
}
static void single_disable_refusal(void) {
    LPVOID original;setup();original=create_at(0);
    require(MTH_EnableHook(target)==MTH_OK,"enable before single-disable refusal");
    peer_ip=(DWORD_PTR)(ULONG_PTR)((BYTE*)original+2);fail_write_protect=TRUE;
    require(MTH_DisableHook(target)==MTH_ERROR_MEMORY_PROTECT && target[0]==0xe9,"single disable fails before changing target bytes");
    require(peer_ip==(DWORD_PTR)(ULONG_PTR)((BYTE*)original+2),"unwritten disable cannot resume peer at still-patched target");
    fail_write_protect=FALSE;require(MTH_DisableHook(target)==MTH_OK,"retry single disable");finish();
}
static void repair_failure(BOOL read) {
    LPVOID original;unsigned before;setup();original=create_at(0);peer_ip=(DWORD_PTR)(ULONG_PTR)target;
    fail_write_protect=TRUE;before=resumes;
    if(read)fail_context_read_after=1;else fail_context_destination=(DWORD_PTR)(ULONG_PTR)target;
    require(MTH_EnableHook(target)==MTH_ERROR_MEMORY_PROTECT && target[0]==0x90,"pre-write failure triggers peer repair");
    require(peer_ip==(DWORD_PTR)(ULONG_PTR)original && resumes==before && HasRetainedThreadOwnership(),"failed IP repair retains suspended peers and original-IP journal");
    require(MTH_ApplyQueued()==MTH_ERROR_MEMORY_PROTECT && resumes==before,"persistent repair failure blocks even no-op mutation");
    fail_context_read_after=0;fail_context_destination=0;fail_write_protect=FALSE;
    require(MTH_ApplyQueued()==MTH_OK && peer_ip==(DWORD_PTR)(ULONG_PTR)target && !HasRetainedThreadOwnership(),"repair retry restores original IP before releasing peer ownership");
    require(resumes==before+1,"repair retry resumes the owned peer exactly once");finish();
}
static void late_birth(BOOL retirement) {
    setup();create_at(0);peer_ip=(DWORD_PTR)(ULONG_PTR)target;late_peer=TRUE;scans=0;
    if(retirement)
        require(MTH_RemoveHook(target)==MTH_ERROR_MEMORY_PROTECT,"late peer rejects generated-code retirement");
    else
        require(MTH_EnableHook(target)==MTH_ERROR_MEMORY_PROTECT,"peer born after enumeration rejects mutation before patching");
    require(target[0]==0x90 && peer_ip==(DWORD_PTR)(ULONG_PTR)target,"late-peer refusal preserves bytes and original peer IP");
    require(!HasRetainedThreadOwnership() && FindHookEntry(target)!=INVALID_HOOK_POS,"late-peer refusal preserves hook owner and drains acquired peers");
    late_peer=FALSE;scans=0;finish();
}
static void stack_failures(void) {
    setup();create_at(0);fail_stack_read=TRUE;
    require(MTH_Uninitialize()==MTH_ERROR_MEMORY_PROTECT,"unreadable peer stack rejects retirement");
    fail_stack_read=FALSE;short_stack_read=TRUE;
    require(MTH_Uninitialize()==MTH_ERROR_MEMORY_PROTECT,"short stack read rejects retirement");
    short_stack_read=FALSE;finish();
}
static void patch_above_pages(void) {
    DWORD old;LPVOID original;MEMORY_BASIC_INFORMATION region;setup();
    require(VirtualProtect(target,8192,PAGE_EXECUTE_READWRITE,&old),"prepare hotpatch fixture");
    target[4097]=0xc3;target[4098]=0x90;target[4099]=1;
    require(VirtualProtect(target,4096,PAGE_EXECUTE_READ,&old),"first hotpatch page RX");
    original=create_at(4097);(void)original;
    require(g_hooks.pItems[FindHookEntry(target+4097)].patchAbove,"fixture selects seven-byte patch-above range");
    require(MTH_EnableHook(target+4097)==MTH_OK && target[4092]==0xe9 && target[4097]==0xeb,"enable cross-page hotpatch");
    require(VirtualQuery(target+4096,&region,sizeof region) && region.Protect==PAGE_EXECUTE_READWRITE,"hotpatch preserves second-page protection");
    require(MTH_DisableHook(target+4097)==MTH_OK && target[4092]==0x90 && target[4097]==0xc3,"disable restores hotpatch bytes");finish();
}
static void unused_slot_retirement(void) {
    LPVOID original;PMEMORY_BLOCK block;PMEMORY_SLOT unused;unsigned i;
    setup();original=create_at(0);block=g_pMemoryBlocks;unused=block->pFree;
    require(unused!=NULL && (LPVOID)unused!=original,"fixture has distinct occupied and unused slots in one block");
    /* A value in an unused slot/header is not an admitted original pointer.
     * Preserve conservative scanning of the complete occupied slot instead. */
    peer_register=(DWORD_PTR)(ULONG_PTR)unused;
    peer_stack[0]=(DWORD_PTR)(ULONG_PTR)block;
    peer_stack[1]=(DWORD_PTR)(ULONG_PTR)((BYTE*)unused+MEMORY_SLOT_SIZE-1);
    require(MTH_Uninitialize()==MTH_OK,"unused slot and header values do not block whole-engine retirement");
    require(g_hHeap==NULL && g_pMemoryBlocks==NULL,"unused-slot retirement completes on its first call");
    require(VirtualFree(target,0,MEM_RELEASE),"release unused-slot fixture target");target=NULL;

    setup();original=create_at(0);block=g_pMemoryBlocks;
    for(i=0;i<MEMORY_SLOT_SIZE;++i) {
        peer_register=(DWORD_PTR)(ULONG_PTR)((BYTE*)original+i);
        require(MTH_Uninitialize()==MTH_ERROR_MEMORY_PROTECT,"every occupied slot byte in a register blocks retirement");
        peer_register=0;peer_stack[0]=(DWORD_PTR)(ULONG_PTR)((BYTE*)original+i);
        require(MTH_Uninitialize()==MTH_ERROR_MEMORY_PROTECT,"every occupied slot byte on a stack blocks retirement");
        peer_stack[0]=0;
        require(g_hHeap!=NULL && g_pMemoryBlocks==block && !HasRetainedThreadOwnership(),"busy slot preserves allocation and repays peer suspensions");
    }
    finish();
}

static void slot_ownership_lifecycle(void) {
    LPVOID slots[MEMORY_BLOCK_SLOTS];PMEMORY_BLOCK block;unsigned i,j;
    setup();
    for(i=0;i<MEMORY_BLOCK_SLOTS;++i) {
        slots[i]=MthInternal_AllocateBuffer(target);
        require(slots[i]!=NULL,"allocate ownership slots across a block boundary");
        for(j=0;j<MEMORY_SLOT_SIZE;++j)
            require(MthInternal_IsBufferAddress((ULONG_PTR)slots[i]+j),"each allocated slot byte is owned");
    }
    for(block=g_pMemoryBlocks;block;block=block->pNext)
        for(j=0;j<MEMORY_SLOT_SIZE;++j)
            require(!MthInternal_IsBufferAddress((ULONG_PTR)block+j),"allocator header bytes are not published slots");
    /* A failed final release must keep its allocation bit and remain retryable. */
    fail_free=TRUE;
    require(!MthInternal_FreeBuffer(slots[MEMORY_BLOCK_SLOTS-1]),"last-slot release failure preserves ownership");
    require(MthInternal_IsBufferAddress((ULONG_PTR)slots[MEMORY_BLOCK_SLOTS-1]),"failed release remains visible to retirement");
    fail_free=FALSE;
    for(i=0;i<MEMORY_BLOCK_SLOTS;++i) {
        ULONG_PTR address=(ULONG_PTR)slots[i];
        require(MthInternal_FreeBuffer(slots[i]),"retire an allocated ownership slot");
        for(j=0;j<MEMORY_SLOT_SIZE;++j)
            require(!MthInternal_IsBufferAddress(address+j),"released slot bytes no longer count as published entries");
        require(!MthInternal_FreeBuffer((LPVOID)address),"double free cannot corrupt the live ownership map");
    }
    require(g_pMemoryBlocks==NULL,"all ownership blocks retire completely");finish();
}

static void stack_owner_at(LPVOID original,SIZE_T offset,SIZE_T start,SIZE_T split,UINT interior) {
    DWORD_PTR value=(DWORD_PTR)(ULONG_PTR)((BYTE*)original+interior);
    unsigned before=resumes;BYTE snapshot[16];HANDLE heap=g_hHeap;
    PMEMORY_BLOCK block=g_pMemoryBlocks;
    require(start<=offset && offset+sizeof(value)<=sizeof(peer_stack),"stack-owner fixture bounds are valid");
    memset(peer_stack,0,sizeof(peer_stack));memcpy((BYTE*)peer_stack+offset,&value,sizeof(value));
    peer_stack_offset=start;peer_stack_split=split;memcpy(snapshot,target,sizeof(snapshot));
    require(MTH_RemoveHook(target)==MTH_ERROR_MEMORY_PROTECT,"unaligned stack owner blocks removal before release");
    require(MTH_Uninitialize()==MTH_ERROR_MEMORY_PROTECT,"unaligned stack owner blocks whole-engine retirement");
    require(g_hHeap==heap && g_pMemoryBlocks==block && MthInternal_IsBufferAddress(value) &&
        FindHookEntry(target)!=INVALID_HOOK_POS,"unaligned refusal preserves exact hook heap and slot owners");
    require(resumes==before+2 && !HasRetainedThreadOwnership() && !memcmp(target,snapshot,sizeof(snapshot)),
        "unaligned refusals repay suspensions and preserve all source bytes");
}
static void unaligned_stack_retirement(void) {
    LPVOID original;SIZE_T offset,boundary,start;UINT interior;
    setup();original=create_at(0);
    /* The exact stepping mutation fails at this first offset, before a freed
     * original can ever execute. Projected registers contain no original. */
    stack_owner_at(original,1,0,0,0);
    for(offset=0;offset<sizeof(DWORD_PTR);++offset)
        stack_owner_at(original,offset,0,0,0);
    for(boundary=64*sizeof(DWORD_PTR);boundary<=128*sizeof(DWORD_PTR);boundary+=64*sizeof(DWORD_PTR))
        for(offset=1;offset<sizeof(DWORD_PTR);++offset)
            for(interior=0;interior<2;++interior)
                stack_owner_at(original,boundary-offset,0,0,interior?MEMORY_SLOT_SIZE-1:0);
    /* A first region shorter than one pointer and an odd region boundary must
     * both retain overlap; include non-aligned captured stack pointers. */
    for(boundary=1;boundary<sizeof(DWORD_PTR);++boundary)
        stack_owner_at(original,0,0,boundary,0);
    boundary=3*sizeof(DWORD_PTR)+1;
    for(offset=1;offset<sizeof(DWORD_PTR);++offset)
        stack_owner_at(original,boundary-offset,0,boundary,0);
    for(start=1;start<sizeof(DWORD_PTR);++start)
        stack_owner_at(original,start+1,start,0,0);
    stack_owner_at(original,sizeof(peer_stack)-sizeof(DWORD_PTR),1,0,MEMORY_SLOT_SIZE-1);
    memset(peer_stack,0,sizeof(peer_stack));peer_stack_offset=peer_stack_split=0;finish();
    /* No complete pointer fits in this final tail: do not read past it or
     * invent a full address from bytes outside the stack allocation. */
    setup();create_at(0);peer_stack_offset=sizeof(peer_stack)-sizeof(DWORD_PTR)+1;finish();
}
static void segmented_stack_failures(void) {
    unsigned mode;setup();create_at(0);peer_stack_split=sizeof(DWORD_PTR)-1;
    for(mode=0;mode<7;++mode) {
        unsigned before=resumes;HANDLE heap=g_hHeap;stack_reads=0;
        fail_stack_read_after=mode==0?1:0;short_stack_read_after=mode==1?1:0;
        fail_stack_query=mode==2;bad_stack_region=mode>=3 && mode<=5?mode-2:0;
        oversized_stack_region=mode==6;
        require(MTH_Uninitialize()==MTH_ERROR_MEMORY_PROTECT,"incomplete split-stack scan refuses retirement");
        require(g_hHeap==heap && g_pMemoryBlocks!=NULL && !HasRetainedThreadOwnership() && resumes==before+1,
            "split-stack read/query/protection/budget failure retains storage and repays suspension");
        require(stack_reads==(mode<=1?2:mode==6?0:1),"split-stack failure occurs at its exact read or region boundary");
    }
    fail_stack_read_after=short_stack_read_after=0;fail_stack_query=oversized_stack_region=FALSE;
    bad_stack_region=0;peer_stack_split=0;finish();
}

static void partial_block_retirement(void) {
    HANDLE owner;unsigned i;setup();
    for(i=0;i<MEMORY_BLOCK_SIZE/MEMORY_SLOT_SIZE+6;++i)create_at(i*32);
    owner=g_hHeap;fail_free_after=1;
    require(MTH_Uninitialize()==MTH_ERROR_MEMORY_PROTECT && free_calls==2,"second block-release failure follows one successful release");
    require(g_hHeap==owner && g_pMemoryBlocks!=NULL && g_pMemoryBlocks->pNext==NULL,"partial retirement keeps the sole remaining block and heap");
    require(MTH_QueueEnableHook(target)==MTH_ERROR_MEMORY_PROTECT,"partial retirement prohibits reusing stale hook entries");
    require(MTH_Uninitialize()==MTH_ERROR_MEMORY_PROTECT && free_calls==3,"retry touches only the remaining block");
    fail_free_after=0;finish();
}
int main(int argc,char** argv) {
    const char* mode=argc>1?argv[1]:"all";
    if(!strcmp(mode,"all")||!strcmp(mode,"restore"))completion_retry(FALSE);
    if(!strcmp(mode,"all")||!strcmp(mode,"cache"))completion_retry(TRUE);
    if(!strcmp(mode,"all")||!strcmp(mode,"prewrite"))prewrite_retirement();
    if(!strcmp(mode,"all")||!strcmp(mode,"free"))release_retry(FALSE);
    if(!strcmp(mode,"all")||!strcmp(mode,"heap"))release_retry(TRUE);
    if(!strcmp(mode,"all")||!strcmp(mode,"pages"))page_protections();
    if(!strcmp(mode,"all")||!strcmp(mode,"unpublished"))unpublished_failure();
    if(!strcmp(mode,"partial-disable"))partial_disable(FALSE);
    if(!strcmp(mode,"late-peer"))late_birth(FALSE);
    if(!strcmp(mode,"unused-slot"))unused_slot_retirement();
    if(!strcmp(mode,"unaligned-stack"))unaligned_stack_retirement();
    if(!strcmp(mode,"all")){partial_batch();partial_disable(FALSE);partial_disable(TRUE);single_disable_refusal();repair_failure(FALSE);repair_failure(TRUE);late_birth(FALSE);late_birth(TRUE);partial_preparation();stack_failures();patch_above_pages();partial_block_retirement();unused_slot_retirement();slot_ownership_lifecycle();unaligned_stack_retirement();segmented_stack_failures();}
    require(checks!=0,"known completion test mode required");
    printf("PASS: %u completion, control-flow, retirement and page checks (projected peers)\n",checks);
    return 0;
}
