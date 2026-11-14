/*
 *  MinHook - The Minimalistic API Hooking Library for x64/x86
 *  Copyright (C) 2009-2017 Tsuda Kageyu.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 *  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
 *  OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


/* SAFE-FREEZE additions derive from the recorded project/donor implementation.
 * The code owner authorized BSD-2-Clause licensing on 2026-11-10.
 * Preserve the upstream BSD notices above and see LICENSE.SAFE_FREEZE and
 * SAFE_FREEZE_LICENSE_NOTICE.md for the contribution and provenance record.
 */
#include <windows.h>
#include <tlhelp32.h>
#include <limits.h>

#include "../include/MithrilHook.h"
#include "buffer.h"
#include "trampoline.h"

#ifndef ARRAYSIZE
    #define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif


/* Temporary bounded diagnosis: fixed storage only during peer suspension. */
static struct { ULONG_PTR stage, action, peer, peers, line, error, ip, sp, match, aux, slot; } mthTrace;
#define MTH_TRACE_FAIL(at, extra) do { if (!mthTrace.line) { mthTrace.line=__LINE__; mthTrace.error=GetLastError(); mthTrace.match=(ULONG_PTR)(at); mthTrace.aux=(ULONG_PTR)(extra); } } while(0)
static void MthDumpTrace(void)
{
    static const char *keys[]={"stage","action","peer","peers","line","error","ip","sp","match","aux","slot"};
    ULONG_PTR values[]={mthTrace.stage,mthTrace.action,mthTrace.peer,mthTrace.peers,mthTrace.line,mthTrace.error,mthTrace.ip,mthTrace.sp,mthTrace.match,mthTrace.aux,mthTrace.slot};
    char text[512]; const char *prefix="RETIRE_TRACE"; unsigned n=0,i,j; DWORD written;
    while(*prefix)text[n++]=*prefix++;
    for(i=0;i<11;++i) { const char *key=keys[i];text[n++]=' ';while(*key)text[n++]=*key++;text[n++]='=';text[n++]='0';text[n++]='x';
        for(j=0;j<sizeof(ULONG_PTR)*2;++j)text[n++]="0123456789abcdef"[(values[i]>>((sizeof(ULONG_PTR)*2-1-j)*4))&15]; }
    text[n++]='\n';WriteFile(GetStdHandle(STD_ERROR_HANDLE),text,n,&written,NULL);
}

// Initial capacity of the HOOK_ENTRY buffer.
#define INITIAL_HOOK_CAPACITY   32

// Initial capacity of the thread IDs buffer.
#define INITIAL_THREAD_CAPACITY 128

// Special hook position values.
#define INVALID_HOOK_POS UINT_MAX
#define ALL_HOOKS_POS    UINT_MAX

// Freeze() action argument defines.
#define ACTION_DISABLE      0
#define ACTION_ENABLE       1
#define ACTION_APPLY_QUEUED 2

// Thread access rights for suspending/resuming threads.
#define THREAD_ACCESS \
    (THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT)

// Hook information.
typedef struct _HOOK_ENTRY
{
    LPVOID pTarget;             // Address of the target function.
    LPVOID pDetour;             // Address of the detour or relay function.
    LPVOID pTrampoline;         // Address of the trampoline function.
    UINT8  backup[8];           // Original prologue of the target function.

    UINT8  patchAbove  : 1;     // Uses the hot patch area.
    UINT8  isEnabled   : 1;     // Enabled.
    UINT8  queueEnable : 1;     // Queued for enabling/disabling when != isEnabled.
    UINT8  freezeEnabled : 1;   // Physical state before the current peer transaction.

    UINT   nIP : 4;             // Count of the instruction boundaries.
    UINT8  oldIPs[8];           // Instruction boundaries of the target function.
    UINT8  newIPs[8];           // Instruction boundaries of the trampoline function.
} HOOK_ENTRY, *PHOOK_ENTRY;

// Suspended threads for Freeze()/Unfreeze().
typedef struct _FROZEN_THREAD_ITEM
{
    HANDLE handle;
    BOOL   suspended;
    DWORD  threadId;
    BOOL   ipCaptured;
    DWORD_PTR originalIP;
} FROZEN_THREAD_ITEM, *PFROZEN_THREAD_ITEM;

typedef struct _FROZEN_THREADS
{
    PFROZEN_THREAD_ITEM pItems; // Exact physical owners retained until release succeeds.
    UINT                capacity;
    UINT                size;
} FROZEN_THREADS, *PFROZEN_THREADS;

//-------------------------------------------------------------------------
// Global Variables:
//-------------------------------------------------------------------------

// Spin lock flag for EnterSpinLock()/LeaveSpinLock().
static volatile LONG g_isLocked = FALSE;
static volatile LONG g_ownerThreadId = 0;

// Private heap handle. If not NULL, this library is initialized.
static HANDLE g_hHeap = NULL;
static BOOL g_ipTransactionActive;

// Hook entries.
static struct
{
    PHOOK_ENTRY pItems;     // Data heap
    UINT        capacity;   // Size of allocated data heap, items
    UINT        size;       // Actual number of data items
} g_hooks;

//-------------------------------------------------------------------------
// Returns INVALID_HOOK_POS if not found.
static UINT FindHookEntry(LPVOID pTarget)
{
    UINT i;
    for (i = 0; i < g_hooks.size; ++i)
    {
        if ((ULONG_PTR)pTarget == (ULONG_PTR)g_hooks.pItems[i].pTarget)
            return i;
    }

    return INVALID_HOOK_POS;
}

/* Disabled entries still own their future physical writes. The engine lock
 * covers this check and publication, so two entries cannot reserve the same
 * bytes. Use the actual hotpatch range, not only the target address. */
static BOOL IsPatchIntervalAvailable(ULONG_PTR start, SIZE_T size)
{
    UINT index;
    ULONG_PTR limit = ~(ULONG_PTR)0;
    if (size == 0 || size > limit - start)
        return FALSE;
    for (index = 0; index < g_hooks.size; ++index)
    {
        const HOOK_ENTRY *hook = &g_hooks.pItems[index];
        ULONG_PTR owned = (ULONG_PTR)hook->pTarget;
        SIZE_T ownedSize = sizeof(JMP_REL);
        if (hook->patchAbove)
        {
            if (owned < sizeof(JMP_REL))
                return FALSE;
            owned -= sizeof(JMP_REL);
            ownedSize += sizeof(JMP_REL_SHORT);
        }
        if (ownedSize > limit - owned)
            return FALSE;
        if (start < owned + ownedSize && owned < start + size)
            return FALSE;
    }
    return TRUE;
}

static BOOL IsHookPatchAvailable(const TRAMPOLINE *ct)
{
    ULONG_PTR start = (ULONG_PTR)ct->pTarget;
    SIZE_T size = sizeof(JMP_REL);
    if (ct->patchAbove)
    {
        if (start < sizeof(JMP_REL))
            return FALSE;
        start -= sizeof(JMP_REL);
        size += sizeof(JMP_REL_SHORT);
    }
    return IsPatchIntervalAvailable(start, size);
}

//-------------------------------------------------------------------------
static PHOOK_ENTRY AddHookEntry()
{
    if (g_hooks.pItems == NULL)
    {
        g_hooks.capacity = INITIAL_HOOK_CAPACITY;
        g_hooks.pItems = (PHOOK_ENTRY)HeapAlloc(
            g_hHeap, 0, g_hooks.capacity * sizeof(HOOK_ENTRY));
        if (g_hooks.pItems == NULL)
            return NULL;
    }
    else if (g_hooks.size >= g_hooks.capacity)
    {
        PHOOK_ENTRY p = (PHOOK_ENTRY)HeapReAlloc(
            g_hHeap, 0, g_hooks.pItems, (g_hooks.capacity * 2) * sizeof(HOOK_ENTRY));
        if (p == NULL)
            return NULL;

        g_hooks.capacity *= 2;
        g_hooks.pItems = p;
    }

    return &g_hooks.pItems[g_hooks.size++];
}

//-------------------------------------------------------------------------
static VOID DeleteHookEntry(UINT pos)
{
    if (pos < g_hooks.size - 1)
        g_hooks.pItems[pos] = g_hooks.pItems[g_hooks.size - 1];

    g_hooks.size--;

    if (g_hooks.capacity / 2 >= INITIAL_HOOK_CAPACITY && g_hooks.capacity / 2 >= g_hooks.size)
    {
        PHOOK_ENTRY p = (PHOOK_ENTRY)HeapReAlloc(
            g_hHeap, 0, g_hooks.pItems, (g_hooks.capacity / 2) * sizeof(HOOK_ENTRY));
        if (p == NULL)
            return;

        g_hooks.capacity /= 2;
        g_hooks.pItems = p;
    }
}

//-------------------------------------------------------------------------
static DWORD_PTR FindOldIP(PHOOK_ENTRY pHook, DWORD_PTR ip)
{
    UINT i;

    if (pHook->patchAbove && ip == ((DWORD_PTR)pHook->pTarget - sizeof(JMP_REL)))
        return (DWORD_PTR)pHook->pTarget;

    for (i = 0; i < pHook->nIP; ++i)
    {
        if (ip == ((DWORD_PTR)pHook->pTrampoline + pHook->newIPs[i]))
            return (DWORD_PTR)pHook->pTarget + pHook->oldIPs[i];
    }

#if defined(_M_X64) || defined(__x86_64__)
    // Check relay function.
    if (ip == (DWORD_PTR)pHook->pDetour)
        return (DWORD_PTR)pHook->pTarget;
#endif

    return 0;
}

//-------------------------------------------------------------------------
static DWORD_PTR FindNewIP(PHOOK_ENTRY pHook, DWORD_PTR ip)
{
    UINT i;
    for (i = 0; i < pHook->nIP; ++i)
    {
        if (ip == ((DWORD_PTR)pHook->pTarget + pHook->oldIPs[i]))
            return (DWORD_PTR)pHook->pTrampoline + pHook->newIPs[i];
    }

    return 0;
}

//-------------------------------------------------------------------------
typedef enum _PEER_PREPARATION_RESULT
{
    PEER_PREPARED = 0,
    PEER_TERMINATED = 1,
    PEER_UNRESOLVED = 2
} PEER_PREPARATION_RESULT;

static BOOL ThreadNoLongerLive(HANDLE hThread)
{
    DWORD exitCode = STILL_ACTIVE;
    if (GetExitCodeThread(hThread, &exitCode))
        return exitCode != STILL_ACTIVE;
    return GetLastError() == ERROR_INVALID_HANDLE;
}

static PEER_PREPARATION_RESULT ProcessThreadIPs(PFROZEN_THREAD_ITEM item, UINT pos, UINT action)
{
    HANDLE hThread = item->handle;
    CONTEXT c;
#if defined(_M_X64) || defined(__x86_64__)
    DWORD64 *pIP = &c.Rip;
#else
    DWORD   *pIP = &c.Eip;
#endif
    UINT count;

    c.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &c))
        return ThreadNoLongerLive(hThread) ? PEER_TERMINATED : PEER_UNRESOLVED;
    item->originalIP = (DWORD_PTR)*pIP;
    item->ipCaptured = TRUE;

    if (pos == ALL_HOOKS_POS)
    {
        pos = 0;
        count = g_hooks.size;
    }
    else
    {
        count = pos + 1;
    }

    for (; pos < count; ++pos)
    {
        PHOOK_ENTRY pHook = &g_hooks.pItems[pos];
        BOOL        enable;
        DWORD_PTR   ip;

        switch (action)
        {
        case ACTION_DISABLE:
            enable = FALSE;
            break;
        case ACTION_ENABLE:
            enable = TRUE;
            break;
        default:
            enable = pHook->queueEnable;
            break;
        }
        if (pHook->isEnabled == enable)
            continue;

        if (enable)
            ip = FindNewIP(pHook, *pIP);
        else
            ip = FindOldIP(pHook, *pIP);

        if (ip != 0)
        {
            *pIP = ip;
            if (!SetThreadContext(hThread, &c))
                return ThreadNoLongerLive(hThread) ? PEER_TERMINATED : PEER_UNRESOLVED;
        }
    }
    return PEER_PREPARED;
}

/* Preparation may have moved a peer before a later peer or target fails.
 * Rebuild its destination from the original IP and only physically written
 * hook transitions. Never resume on an unresolved context repair. */
static BOOL ReconcileThreadIPs(PFROZEN_THREADS pThreads)
{
    UINT i, pos;
    BOOL complete = TRUE;
    if (!g_ipTransactionActive)
        return TRUE;
    for (i = 0; i < pThreads->size; ++i)
    {
        PFROZEN_THREAD_ITEM item = &pThreads->pItems[i];
        CONTEXT context;
        DWORD_PTR desired;
        if (!item->ipCaptured)
            continue;
        if (ThreadNoLongerLive(item->handle))
        {
            item->ipCaptured = FALSE;
            continue;
        }
        context.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(item->handle, &context))
        {
            if (ThreadNoLongerLive(item->handle))
                item->ipCaptured = FALSE;
            else
                complete = FALSE;
            continue;
        }
        desired = item->originalIP;
        for (pos = 0; pos < g_hooks.size; ++pos)
        {
            PHOOK_ENTRY hook = &g_hooks.pItems[pos];
            DWORD_PTR ip;
            if (hook->freezeEnabled == hook->isEnabled)
                continue;
            ip = hook->isEnabled ? FindNewIP(hook, desired) : FindOldIP(hook, desired);
            if (ip != 0)
                desired = ip;
        }
#if defined(_M_X64) || defined(__x86_64__)
        if (context.Rip != desired)
        {
            context.Rip = desired;
#else
        if (context.Eip != desired)
        {
            context.Eip = (DWORD)desired;
#endif
            if (!SetThreadContext(item->handle, &context))
            {
                if (ThreadNoLongerLive(item->handle))
                    item->ipCaptured = FALSE;
                else
                    complete = FALSE;
                continue;
            }
        }
        item->ipCaptured = FALSE;
    }
    if (complete)
        g_ipTransactionActive = FALSE;
    return complete;
}

//-------------------------------------------------------------------------
/* MTH_SAFE_FREEZE_V1
 *
 * The inherited engine enumerated peer threads with CreateToolhelp32Snapshot.
 * Strict mode uses stable owned handles and rejects unresolved peers.
 * Keep MithrilHook's suspend/context/IP-relocation contract, but enumerate stable
 * thread handles with NtGetNextThread instead. Callers must avoid loader lock.
 *
 * Retained ownership rule: every duplicated peer HANDLE and the backing heap array
 * remain discoverable until ResumeThread/CloseHandle/HeapFree physically
 * succeed or the handle is proven terminated/invalid. A later MithrilHook operation
 * retries retained cleanup before acquiring a new peer-thread set.
 */
typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *PFN_NT_GET_NEXT_THREAD)(
    HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#endif

/* Completion records outlive failed API calls. No allocation is needed while
 * peers are suspended. A seven-byte hotpatch can touch at most two pages. */
typedef struct _PATCH_PAGE
{
    LPVOID address;
    DWORD protection;
    BOOL pending;
} PATCH_PAGE;
static struct
{
    BOOL active, cachePending;
    LPBYTE target;
    SIZE_T size, pageSize;
    UINT count;
    PATCH_PAGE pages[2];
} g_patchCompletion;
static LPVOID g_retainedBuffer;
static BOOL g_shutdownPending;
static LPVOID g_retiringBuffer;
#define ACTION_RETIRE 3

static BOOL RetryPatchCompletion(VOID)
{
    UINT i;
    BOOL complete = TRUE;
    if (!g_patchCompletion.active)
        return TRUE;
    if (g_patchCompletion.cachePending)
    {
        if (FlushInstructionCache(GetCurrentProcess(), g_patchCompletion.target, g_patchCompletion.size))
            g_patchCompletion.cachePending = FALSE;
        else
            complete = FALSE;
    }
    for (i = 0; i < g_patchCompletion.count; ++i)
    {
        PATCH_PAGE *page = &g_patchCompletion.pages[i];
        if (page->pending)
        {
            DWORD ignored;
            if (VirtualProtect(page->address, g_patchCompletion.pageSize, page->protection, &ignored))
                page->pending = FALSE;
            else
                complete = FALSE;
        }
    }
    if (complete)
        memset(&g_patchCompletion, 0, sizeof(g_patchCompletion));
    return complete;
}

static BOOL IsRetiringAddress(DWORD_PTR address)
{
    if (g_retiringBuffer != NULL)
        return address >= (ULONG_PTR)g_retiringBuffer &&
            address - (ULONG_PTR)g_retiringBuffer < MEMORY_SLOT_SIZE;
    return MthInternal_IsBufferAddress((ULONG_PTR)address);
}

static PEER_PREPARATION_RESULT CheckRetiringThread(HANDLE thread)
{
    CONTEXT context;
    MEMORY_BASIC_INFORMATION first;
    ULONG_PTR cursor, allocation;
    SIZE_T scanned = 0;
    DWORD_PTR registers[17];
    UINT i, count;
    context.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(thread, &context))
        { MTH_TRACE_FAIL(0, 1); return ThreadNoLongerLive(thread) ? PEER_TERMINATED : PEER_UNRESOLVED; }
#if defined(_M_X64) || defined(__x86_64__)
    registers[0]=context.Rip; registers[1]=context.Rax; registers[2]=context.Rbx;
    registers[3]=context.Rcx; registers[4]=context.Rdx; registers[5]=context.Rsi;
    registers[6]=context.Rdi; registers[7]=context.Rbp; registers[8]=context.Rsp;
    registers[9]=context.R8; registers[10]=context.R9; registers[11]=context.R10;
    registers[12]=context.R11; registers[13]=context.R12; registers[14]=context.R13;
    registers[15]=context.R14; registers[16]=context.R15;
    count = 17;
    cursor = (ULONG_PTR)context.Rsp;
#else
    registers[0]=context.Eip; registers[1]=context.Eax; registers[2]=context.Ebx;
    registers[3]=context.Ecx; registers[4]=context.Edx; registers[5]=context.Esi;
    registers[6]=context.Edi; registers[7]=context.Ebp; registers[8]=context.Esp;
    count = 9;
    cursor = (ULONG_PTR)context.Esp;
#endif
    mthTrace.ip=registers[0];mthTrace.sp=cursor;
    for (i = 0; i < count; ++i)
        if (IsRetiringAddress(registers[i]))
            { MTH_TRACE_FAIL(registers[i], i); return PEER_UNRESOLVED; }
    if (!VirtualQuery((LPCVOID)cursor, &first, sizeof(first)))
        { MTH_TRACE_FAIL(cursor, 4); return PEER_UNRESOLVED; }
    allocation = (ULONG_PTR)first.AllocationBase;
    while (scanned < 64 * 1024 * 1024)
    {
        MEMORY_BASIC_INFORMATION region;
        ULONG_PTR limit;
        if (!VirtualQuery((LPCVOID)cursor, &region, sizeof(region)))
            { MTH_TRACE_FAIL(cursor, 2); return PEER_UNRESOLVED; }
        if ((ULONG_PTR)region.AllocationBase != allocation)
            return PEER_PREPARED;
        limit = (ULONG_PTR)region.BaseAddress + region.RegionSize;
        if (limit <= cursor || limit - cursor > 64 * 1024 * 1024 - scanned ||
            region.State != MEM_COMMIT || (region.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
            { MTH_TRACE_FAIL(cursor, 2); return PEER_UNRESOLVED; }
        while (cursor < limit)
        {
            DWORD_PTR words[64];
            SIZE_T copied = 0, bytes = limit - cursor;
            if (bytes > sizeof(words)) bytes = sizeof(words);
            if (bytes % sizeof(words[0]) != 0 ||
                !ReadProcessMemory(GetCurrentProcess(), (LPCVOID)cursor, words, bytes, &copied) || copied != bytes)
                { MTH_TRACE_FAIL(cursor, 3); return PEER_UNRESOLVED; }
            for (i = 0; i < bytes / sizeof(words[0]); ++i)
                if (IsRetiringAddress(words[i]))
                    { MTH_TRACE_FAIL(words[i], cursor+i*sizeof(words[0])); return PEER_UNRESOLVED; }
            cursor += bytes;
            scanned += bytes;
        }
    }
    { MTH_TRACE_FAIL(cursor, 5); return PEER_UNRESOLVED; }
}

static FROZEN_THREADS g_retainedThreads = { NULL, 0, 0 };
static FROZEN_THREAD_ITEM g_emergencyThread = { NULL, FALSE };
static FROZEN_THREAD_ITEM g_emergencyNextThread = { NULL, FALSE };

static PFN_NT_GET_NEXT_THREAD ResolveNtGetNextThread(VOID)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL)
        return NULL;
    return (PFN_NT_GET_NEXT_THREAD)GetProcAddress(ntdll, "NtGetNextThread");
}

static BOOL AppendThreadHandle(PFROZEN_THREADS pThreads, HANDLE hThread)
{
    if (pThreads->pItems == NULL)
    {
        pThreads->capacity = INITIAL_THREAD_CAPACITY;
        pThreads->pItems = (PFROZEN_THREAD_ITEM)HeapAlloc(
            g_hHeap, HEAP_ZERO_MEMORY,
            pThreads->capacity * sizeof(FROZEN_THREAD_ITEM));
        if (pThreads->pItems == NULL)
            return FALSE;
    }
    else if (pThreads->size >= pThreads->capacity)
    {
        PFROZEN_THREAD_ITEM p;
        UINT oldCapacity = pThreads->capacity;
        pThreads->capacity *= 2;
        p = (PFROZEN_THREAD_ITEM)HeapReAlloc(
            g_hHeap, HEAP_ZERO_MEMORY, pThreads->pItems,
            pThreads->capacity * sizeof(FROZEN_THREAD_ITEM));
        if (p == NULL)
        {
            pThreads->capacity = oldCapacity;
            return FALSE;
        }
        pThreads->pItems = p;
    }
    pThreads->pItems[pThreads->size].handle = hThread;
    pThreads->pItems[pThreads->size].suspended = FALSE;
    pThreads->pItems[pThreads->size].threadId = 0;
    pThreads->pItems[pThreads->size].ipCaptured = FALSE;
    ++pThreads->size;
    return TRUE;
}

static BOOL ResumeOwnedThread(PFROZEN_THREAD_ITEM pItem)
{
    DWORD resumeResult;
    if (pItem->handle == NULL || !pItem->suspended)
        return TRUE;
    if (ThreadNoLongerLive(pItem->handle))
    {
        pItem->suspended = FALSE;
        return TRUE;
    }
    resumeResult = ResumeThread(pItem->handle);
    if (resumeResult != 0xFFFFFFFF)
    {
        pItem->suspended = FALSE;
        return TRUE;
    }
    if (GetLastError() == ERROR_INVALID_HANDLE || ThreadNoLongerLive(pItem->handle))
    {
        pItem->suspended = FALSE;
        return TRUE;
    }
    return FALSE;
}

static BOOL CloseOwnedThread(PFROZEN_THREAD_ITEM pItem)
{
    if (pItem->handle == NULL)
        return TRUE;
    if (CloseHandle(pItem->handle))
    {
        pItem->handle = NULL;
        return TRUE;
    }
    if (GetLastError() == ERROR_INVALID_HANDLE)
    {
        pItem->handle = NULL;
        return TRUE;
    }
    return FALSE;
}

static BOOL CloseOrRetainEmergency(HANDLE hThread)
{
    FROZEN_THREAD_ITEM item = { hThread, FALSE };
    if (CloseOwnedThread(&item))
        return TRUE;
    if (g_emergencyThread.handle == NULL)
    {
        g_emergencyThread = item;
        return FALSE;
    }
    if (g_emergencyNextThread.handle == NULL)
    {
        g_emergencyNextThread = item;
        return FALSE;
    }
    return FALSE;
}

static BOOL ReleaseEmergencyThreadOwnership(VOID)
{
    // One failed cursor-close can coexist with a newly returned next handle.
    // Keep two physically independent emergency owner slots until both close.
    BOOL nextReleased = ResumeOwnedThread(&g_emergencyNextThread);
    if (nextReleased)
        nextReleased = CloseOwnedThread(&g_emergencyNextThread);
    BOOL cursorReleased = ResumeOwnedThread(&g_emergencyThread);
    if (cursorReleased)
        cursorReleased = CloseOwnedThread(&g_emergencyThread);
    return nextReleased && cursorReleased;
}

static BOOL ReleaseFrozenThreadOwnership(PFROZEN_THREADS pThreads)
{
    UINT i;
    BOOL released = TRUE;
    if (pThreads->pItems == NULL)
        return TRUE;
    for (i = 0; i < pThreads->size; ++i)
    {
        PFROZEN_THREAD_ITEM pItem = &pThreads->pItems[i];
        if (!ResumeOwnedThread(pItem))
        {
            released = FALSE;
            continue;
        }
        if (!CloseOwnedThread(pItem))
            released = FALSE;
    }
    if (!released)
        return FALSE;
    if (!HeapFree(g_hHeap, 0, pThreads->pItems))
        return FALSE;
    pThreads->pItems = NULL;
    pThreads->size = 0;
    pThreads->capacity = 0;
    return TRUE;
}

static BOOL PreserveFrozenThreadOwnership(PFROZEN_THREADS pThreads)
{
    if (!g_patchCompletion.active && !MthInternal_HasPendingBufferUnwind() && ReconcileThreadIPs(pThreads) &&
        ReleaseFrozenThreadOwnership(pThreads))
        return TRUE;
    if (g_retainedThreads.pItems != NULL)
        return FALSE; /* Freeze drains this before creating a new owner set. */
    g_retainedThreads = *pThreads;
    pThreads->pItems = NULL;
    pThreads->size = 0;
    pThreads->capacity = 0;
    return FALSE;
}

static BOOL RetryRetainedThreadOwnership(VOID)
{
    /* Never resume peers into an instruction stream whose completion failed. */
    if (!RetryPatchCompletion() ||
        (MthInternal_HasPendingBufferUnwind() && g_retainedThreads.pItems != NULL) ||
        !ReconcileThreadIPs(&g_retainedThreads))
        return FALSE;
    if (!ReleaseEmergencyThreadOwnership() || !ReleaseFrozenThreadOwnership(&g_retainedThreads))
        return FALSE;
    /* RtlAdd/DeleteFunctionTable may acquire locks held by other threads.
     * Registry recovery is therefore outside every owned suspension window. */
    if (!MthInternal_RetryBufferUnwind())
        return FALSE;
    if (g_retainedBuffer != NULL)
    {
        if (!MthInternal_FreeBuffer(g_retainedBuffer))
            return FALSE;
        g_retainedBuffer = NULL;
    }
    return TRUE;
}

static BOOL HasRetainedThreadOwnership(VOID)
{
    return g_emergencyThread.handle != NULL || g_emergencyNextThread.handle != NULL || g_retainedThreads.pItems != NULL;
}

typedef enum _THREAD_ENUMERATION_RESULT
{
    THREAD_ENUMERATION_OK = 0,
    THREAD_ENUMERATION_ALLOC_FAILED = 1,
    THREAD_ENUMERATION_API_FAILED = 2,
    THREAD_ENUMERATION_OWNERSHIP_FAILED = 3
} THREAD_ENUMERATION_RESULT;

static THREAD_ENUMERATION_RESULT EnumerateThreads(PFROZEN_THREADS pThreads)
{
    PFN_NT_GET_NEXT_THREAD getNextThread = ResolveNtGetNextThread();
    HANDLE process = GetCurrentProcess();
    HANDLE cursor = NULL;
    DWORD currentThreadId = GetCurrentThreadId();
    if (getNextThread == NULL)
        return THREAD_ENUMERATION_API_FAILED;

    for (;;)
    {
        HANDLE next = NULL;
        NTSTATUS status = getNextThread(
            process, cursor, THREAD_ACCESS, 0, 0, &next);
        if (cursor != NULL && !CloseOrRetainEmergency(cursor))
        {
            // NtGetNextThread has already returned next. The failed cursor
            // close consumes the first emergency owner slot; retain next in
            // the second slot, even if it has not been suspended yet.
            if (NT_SUCCESS(status) && next != NULL)
                g_emergencyNextThread.handle = next;
            cursor = NULL;
            (void)PreserveFrozenThreadOwnership(pThreads);
            return THREAD_ENUMERATION_OWNERSHIP_FAILED;
        }
        cursor = NULL;
        if (!NT_SUCCESS(status))
        {
            if (status == STATUS_NO_MORE_ENTRIES)
                break;
            return PreserveFrozenThreadOwnership(pThreads)
                ? THREAD_ENUMERATION_API_FAILED
                : THREAD_ENUMERATION_OWNERSHIP_FAILED;
        }
        cursor = next;

        if (GetThreadId(next) != currentThreadId)
        {
            HANDLE owned = NULL;
            if (!DuplicateHandle(
                    process, next, process, &owned, 0, FALSE, DUPLICATE_SAME_ACCESS))
            {
                if (cursor != NULL && !CloseOrRetainEmergency(cursor))
                    cursor = NULL;
                return PreserveFrozenThreadOwnership(pThreads)
                    ? THREAD_ENUMERATION_API_FAILED
                    : THREAD_ENUMERATION_OWNERSHIP_FAILED;
            }
            if (!AppendThreadHandle(pThreads, owned))
            {
                BOOL cleanupOk = CloseOrRetainEmergency(owned);
                if (cursor != NULL && !CloseOrRetainEmergency(cursor))
                    cleanupOk = FALSE;
                if (!PreserveFrozenThreadOwnership(pThreads))
                    cleanupOk = FALSE;
                return cleanupOk
                    ? THREAD_ENUMERATION_ALLOC_FAILED
                    : THREAD_ENUMERATION_OWNERSHIP_FAILED;
            }
            pThreads->pItems[pThreads->size - 1].threadId = GetThreadId(next);
        }
    }
    if (cursor != NULL && !CloseOrRetainEmergency(cursor))
    {
        (void)PreserveFrozenThreadOwnership(pThreads);
        return THREAD_ENUMERATION_OWNERSHIP_FAILED;
    }
    return THREAD_ENUMERATION_OK;
}

/* A second observation after suspension catches peers born during the first
 * enumeration/preparation window. It is not a universal thread-birth barrier. */
static MTH_STATUS VerifyFrozenThreadCoverage(PFROZEN_THREADS pThreads)
{
    PFN_NT_GET_NEXT_THREAD getNextThread = ResolveNtGetNextThread();
    HANDLE cursor = NULL;
    DWORD current = GetCurrentThreadId();
    MTH_STATUS result = MTH_OK;
    if (getNextThread == NULL)
        return MTH_UNKNOWN;
    for (;;)
    {
        HANDLE next = NULL;
        NTSTATUS status = getNextThread(GetCurrentProcess(), cursor, THREAD_ACCESS, 0, 0, &next);
        DWORD id;
        UINT i;
        BOOL covered = FALSE;
        if (cursor != NULL && !CloseOrRetainEmergency(cursor))
        {
            if (NT_SUCCESS(status) && next != NULL)
                g_emergencyNextThread.handle = next;
            return MTH_ERROR_MEMORY_PROTECT;
        }
        cursor = NULL;
        if (!NT_SUCCESS(status))
            return status == STATUS_NO_MORE_ENTRIES ? MTH_OK : MTH_UNKNOWN;
        cursor = next;
        id = GetThreadId(cursor);
        if (id == current)
            continue;
        if (id != 0)
            for (i = 0; i < pThreads->size; ++i)
                if (pThreads->pItems[i].threadId == id &&
                    pThreads->pItems[i].suspended &&
                    !ThreadNoLongerLive(pThreads->pItems[i].handle))
                {
                    covered = TRUE;
                    break;
                }
        if (!covered && !ThreadNoLongerLive(cursor))
        {
            MTH_TRACE_FAIL(id, 8);
            result = MTH_ERROR_MEMORY_PROTECT;
            break;
        }
    }
    return CloseOrRetainEmergency(cursor) ? result : MTH_ERROR_MEMORY_PROTECT;
}

//-------------------------------------------------------------------------
static MTH_STATUS Freeze(PFROZEN_THREADS pThreads, UINT pos, UINT action)
{
    MTH_STATUS status = MTH_OK;
    pThreads->pItems   = NULL;
    pThreads->capacity = 0;
    pThreads->size     = 0;

    mthTrace.action=action;
    if (!RetryRetainedThreadOwnership())
        { MTH_TRACE_FAIL(0, 6); return MTH_ERROR_MEMORY_PROTECT; }
    {
        THREAD_ENUMERATION_RESULT enumeration = EnumerateThreads(pThreads);
        if (enumeration != THREAD_ENUMERATION_OK)
        {
            if (enumeration == THREAD_ENUMERATION_ALLOC_FAILED)
                return MTH_ERROR_MEMORY_ALLOC;
            if (enumeration == THREAD_ENUMERATION_OWNERSHIP_FAILED ||
                HasRetainedThreadOwnership())
                return MTH_ERROR_MEMORY_PROTECT;
            // OS/API enumeration failure is not allocation
            // failure. Preserve MithrilHook's public ABI and report its generic
            // non-allocation failure status rather than lying about memory.
            return MTH_UNKNOWN;
        }
    }
    if (action != ACTION_RETIRE)
    {
        UINT i;
        for (i = 0; i < g_hooks.size; ++i)
            g_hooks.pItems[i].freezeEnabled = g_hooks.pItems[i].isEnabled;
        g_ipTransactionActive = TRUE;
    }
    if (pThreads->pItems != NULL)
    {
        UINT i;
        for (i = 0; i < pThreads->size; ++i)
        {
            PFROZEN_THREAD_ITEM pItem = &pThreads->pItems[i];
            if (pItem->handle == NULL)
                continue;
            mthTrace.peer=pItem->threadId;mthTrace.peers=pThreads->size;
            if (SuspendThread(pItem->handle) != 0xFFFFFFFF)
            {
                PEER_PREPARATION_RESULT peerResult;
                pItem->suspended = TRUE;
                peerResult = action == ACTION_RETIRE ? CheckRetiringThread(pItem->handle) : ProcessThreadIPs(pItem, pos, action);
                if (peerResult == PEER_UNRESOLVED)
                    status = MTH_ERROR_MEMORY_PROTECT;
            }
            else if (!ThreadNoLongerLive(pItem->handle))
            {
                MTH_TRACE_FAIL(pItem->handle, 7);
                status = MTH_ERROR_MEMORY_PROTECT;
            }
        }
    }
    if (status == MTH_OK)
        status = VerifyFrozenThreadCoverage(pThreads);
    if (status != MTH_OK)
        (void)PreserveFrozenThreadOwnership(pThreads);
    return status;
}

//-------------------------------------------------------------------------
static MTH_STATUS Unfreeze(PFROZEN_THREADS pThreads)
{
    return PreserveFrozenThreadOwnership(pThreads)
        ? MTH_OK
        : MTH_ERROR_MEMORY_PROTECT;
}

static MTH_STATUS FinishFreeze(PFROZEN_THREADS pThreads, MTH_STATUS status)
{
    MTH_STATUS cleanupStatus;
    if (g_patchCompletion.active)
    {
        /* Freeze entered with no retained set. Transfer without resuming. */
        g_retainedThreads = *pThreads;
        memset(pThreads, 0, sizeof(*pThreads));
        return MTH_ERROR_MEMORY_PROTECT;
    }
    cleanupStatus = Unfreeze(pThreads);
    return status == MTH_OK ? cleanupStatus : status;
}

//-------------------------------------------------------------------------
static MTH_STATUS RetireHookEntry(UINT pos)
{
    FROZEN_THREADS threads;
    MTH_STATUS status;
    g_retiringBuffer = g_hooks.pItems[pos].pTrampoline;
    status = Freeze(&threads, ALL_HOOKS_POS, ACTION_RETIRE);
    /* Admission must stay closed across this observation/resume/release phase.
     * Runtime-table deletion cannot run while a suspended peer holds its lock. */
    if (status == MTH_OK)
        status = FinishFreeze(&threads, status);
    if (status == MTH_OK)
    {
        if (MthInternal_FreeBuffer(g_hooks.pItems[pos].pTrampoline))
            DeleteHookEntry(pos);
        else
            status = MTH_ERROR_MEMORY_PROTECT;
    }
    g_retiringBuffer = NULL;
    return status;
}

static MTH_STATUS RetireAllBuffers(VOID)
{
    FROZEN_THREADS threads;
    MTH_STATUS status;
    g_retiringBuffer = NULL;
    status = Freeze(&threads, ALL_HOOKS_POS, ACTION_RETIRE);
    if (status == MTH_OK)
        status = FinishFreeze(&threads, status);
    if (status == MTH_OK)
    {
        /* Some blocks may be released before a later release fails. */
        g_shutdownPending = TRUE;
        if (!MthInternal_UninitializeBuffer())
            status = MTH_ERROR_MEMORY_PROTECT;
    }
    return status;
}

static MTH_STATUS EnableHookLL(UINT pos, BOOL enable)
{
    PHOOK_ENTRY pHook = &g_hooks.pItems[pos];
    SIZE_T patchSize = sizeof(JMP_REL);
    LPBYTE target = (LPBYTE)pHook->pTarget;
    SYSTEM_INFO info;
    ULONG_PTR first, last;
    UINT i;
    if (g_patchCompletion.active)
        return MTH_ERROR_MEMORY_PROTECT;
    if (pHook->patchAbove)
    {
        target -= sizeof(JMP_REL);
        patchSize += sizeof(JMP_REL_SHORT);
    }
    GetSystemInfo(&info);
    if (!info.dwPageSize || patchSize > info.dwPageSize || (ULONG_PTR)target > (ULONG_PTR)-1 - patchSize)
        return MTH_ERROR_MEMORY_PROTECT;
    first = (ULONG_PTR)target / info.dwPageSize * info.dwPageSize;
    last = ((ULONG_PTR)target + patchSize - 1) / info.dwPageSize * info.dwPageSize;
    memset(&g_patchCompletion, 0, sizeof(g_patchCompletion));
    g_patchCompletion.active = TRUE;
    g_patchCompletion.target = target;
    g_patchCompletion.size = patchSize;
    g_patchCompletion.pageSize = info.dwPageSize;
    g_patchCompletion.count = first == last ? 1 : 2;
    for (i = 0; i < g_patchCompletion.count; ++i)
    {
        PATCH_PAGE *page = &g_patchCompletion.pages[i];
        page->address = (LPVOID)(first + i * info.dwPageSize);
        if (!VirtualProtect(page->address, info.dwPageSize, PAGE_EXECUTE_READWRITE, &page->protection))
        {
            (void)RetryPatchCompletion();
            return MTH_ERROR_MEMORY_PROTECT;
        }
        page->pending = TRUE;
    }
    if (enable)
    {
        PJMP_REL jump = (PJMP_REL)target;
        jump->opcode = 0xE9;
        jump->operand = (INT32)((LPBYTE)pHook->pDetour - (target + sizeof(JMP_REL)));
        if (pHook->patchAbove)
        {
            PJMP_REL_SHORT shortJump = (PJMP_REL_SHORT)pHook->pTarget;
            shortJump->opcode = 0xEB;
            shortJump->operand = (INT8)(0 - (sizeof(JMP_REL_SHORT) + sizeof(JMP_REL)));
        }
    }
    else
        memcpy(target, pHook->backup, patchSize);
    /* Reflect the bytes already written even if subsequent completion fails. */
    pHook->isEnabled = enable;
    pHook->queueEnable = enable;
    g_patchCompletion.cachePending = TRUE;
    return RetryPatchCompletion() ? MTH_OK : MTH_ERROR_MEMORY_PROTECT;
}

//-------------------------------------------------------------------------
static MTH_STATUS EnableAllHooksLL(BOOL enable)
{
    MTH_STATUS status = MTH_OK;
    if (!RetryRetainedThreadOwnership())
        return MTH_ERROR_MEMORY_PROTECT;
    UINT i, first = INVALID_HOOK_POS;

    for (i = 0; i < g_hooks.size; ++i)
    {
        if (g_hooks.pItems[i].isEnabled != enable)
        {
            first = i;
            break;
        }
    }

    if (first != INVALID_HOOK_POS)
    {
        FROZEN_THREADS threads;
        status = Freeze(&threads, ALL_HOOKS_POS, enable ? ACTION_ENABLE : ACTION_DISABLE);
        if (status == MTH_OK)
        {
            for (i = first; i < g_hooks.size; ++i)
            {
                if (g_hooks.pItems[i].isEnabled != enable)
                {
                    status = EnableHookLL(i, enable);
                    if (status != MTH_OK)
                        break;
                }
            }

            status = FinishFreeze(&threads, status);
        }
    }

    return status;
}

//-------------------------------------------------------------------------
static BOOL EnterSpinLock(VOID)
{
    SIZE_T spinCount = 0;
    const DWORD threadId = GetCurrentThreadId();
    if ((DWORD)InterlockedCompareExchange(&g_ownerThreadId, 0, 0) == threadId)
        return FALSE;

    // Wait until the flag is FALSE.
    while (InterlockedCompareExchange(&g_isLocked, TRUE, FALSE) != FALSE)
    {
        // No need to generate a memory barrier here, since InterlockedCompareExchange()
        // generates a full memory barrier itself.

        // Prevent the loop from being too busy.
        if (spinCount < 32)
            Sleep(0);
        else
            Sleep(1);

        spinCount++;
    }
    InterlockedExchange(&g_ownerThreadId, (LONG)threadId);
    return TRUE;
}

//-------------------------------------------------------------------------
static VOID LeaveSpinLock(VOID)
{
    // No need to generate a memory barrier here, since InterlockedExchange()
    // generates a full memory barrier itself.

    InterlockedExchange(&g_ownerThreadId, 0);
    InterlockedExchange(&g_isLocked, FALSE);
}

//-------------------------------------------------------------------------
MTH_STATUS WINAPI MTH_Initialize(VOID)
{
    MTH_STATUS status = MTH_OK;

    if (!EnterSpinLock())
        return MTH_ERROR_REENTRANT_CALL;

    if (g_hHeap == NULL)
    {
        g_hHeap = HeapCreate(0, 0, 0);
        if (g_hHeap != NULL)
        {
            // Initialize the internal function buffer.
            MthInternal_InitializeBuffer();
        }
        else
        {
            status = MTH_ERROR_MEMORY_ALLOC;
        }
    }
    else
    {
        status = MTH_ERROR_ALREADY_INITIALIZED;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
MTH_STATUS WINAPI MTH_Uninitialize(VOID)
{
    MTH_STATUS status = MTH_ERROR_NOT_INITIALIZED;
    if (!EnterSpinLock())
        return MTH_ERROR_REENTRANT_CALL;
    memset(&mthTrace,0,sizeof(mthTrace));mthTrace.stage=1;
    mthTrace.slot=g_hooks.size?(ULONG_PTR)g_hooks.pItems[0].pTrampoline:0;
    if (g_hHeap != NULL)
    {
        status = RetryRetainedThreadOwnership() ? MTH_OK : MTH_ERROR_MEMORY_PROTECT;
        if (status == MTH_OK && !g_shutdownPending)
            { mthTrace.stage=2;status = EnableAllHooksLL(FALSE); }
        if (status == MTH_OK)
            { mthTrace.stage=3;status = RetireAllBuffers(); }
        /* Frozen arrays belong to this heap: finish/retry their cleanup before
         * destroying it. HeapDestroy also owns the hook-entry allocation. */
        if (status == MTH_OK)
        {
            mthTrace.stage=4;
            if (!HeapDestroy(g_hHeap))
                status = MTH_ERROR_MEMORY_PROTECT;
            else
            {
                g_hHeap = NULL;
                g_hooks.pItems = NULL;
                g_hooks.size = g_hooks.capacity = 0;
                g_shutdownPending = FALSE;
            }
        }
    }
    if(status!=MTH_OK)MthDumpTrace();
    LeaveSpinLock();
    return status;
}

//-------------------------------------------------------------------------
#if defined(_M_X64) || defined(__x86_64__)
static BOOL IsNonvolatileUnwindRegister(UINT reg)
{
    return reg == 3 || reg == 5 || reg == 6 || reg == 7 || (reg >= 12 && reg <= 15);
}

static BOOL SupportsGeneratedUnwindV2(VOID)
{
    typedef LONG (NTAPI *RTL_GET_VERSION)(LPOSVERSIONINFOW);
    RTL_GET_VERSION getVersion = (RTL_GET_VERSION)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    OSVERSIONINFOW version;
    if (getVersion == NULL)
        return FALSE;
    memset(&version, 0, sizeof(version));
    version.dwOSVersionInfoSize = sizeof(version);
    /* This bounded generated format is supported on Windows 10 and later.
     * Older/unknown systems retain strict refusal of nonleaf relocation. */
    return getVersion(&version) >= 0 && version.dwMajorVersion >= 10;
}

static BOOL MapUnwindOffset(const TRAMPOLINE *ct, UINT offset, BYTE *mapped)
{
    UINT i;
    if (offset == ct->oldSize)
    {
        *mapped = ct->newSize;
        return TRUE;
    }
    for (i = 0; i < ct->nIP; ++i)
        if (ct->oldIPs[i] == offset)
        {
            *mapped = ct->newIPs[i];
            return TRUE;
        }
    return FALSE;
}
#endif

/* Describe only the operations actually present in the relocated prefix.
 * Version 2 has explicit epilogue descriptions; an empty epilogue set prevents
 * FF25 from being mistaken for an already-restored tail-call epilogue. Version 1
 * instruction scanning cannot safely describe this stack-changing jump-back.
 * Language scopes and unknown/chained source formats remain unsupported. */
static BOOL IsRelocationUnwindSafe(const TRAMPOLINE *ct)
{
#if defined(_M_X64) || defined(__x86_64__)
    DWORD64 base = 0;
    PRUNTIME_FUNCTION found = RtlLookupFunctionEntry((DWORD64)(ULONG_PTR)ct->pTarget, &base, NULL);
    RUNTIME_FUNCTION function;
    BYTE info[4 + 255 * 2];
    SIZE_T copied = 0;
    UINT index, count, output = 0, previous = 256;
    UINT flags, frameRegister;
    DWORD64 address;
    PMTH_UNWIND_STORAGE generated = MTH_BUFFER_UNWIND(ct->pTrampoline);
    BOOL copiedFrame = FALSE;
    if (found == NULL)
        return TRUE; /* An ABI-valid unregistered function must already be leaf-unwindable. */
    if (!ReadProcessMemory(GetCurrentProcess(), found, &function, sizeof(function), &copied) ||
        copied != sizeof(function) || function.EndAddress <= function.BeginAddress ||
        ct->oldSize > function.EndAddress - function.BeginAddress ||
        base > (DWORD64)-1 - function.UnwindData ||
        (DWORD64)(ULONG_PTR)ct->pTarget < base ||
        (DWORD64)(ULONG_PTR)ct->pTarget - base != function.BeginAddress)
        return FALSE;
    address = base + function.UnwindData;
    if (address > (DWORD64)-1 - sizeof(info) ||
        !ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(ULONG_PTR)address, info, 4, &copied) || copied != 4)
        return FALSE;
    flags = info[0] >> 3;
    frameRegister = info[3] & 15;
    if ((info[0] & 7) != 1 || (flags & ~3U) != 0 ||
        ((flags & 3) != 0 && ct->oldSize > info[1]) ||
        (frameRegister != 0 && !IsNonvolatileUnwindRegister(frameRegister)))
        return FALSE;
    count = info[2];
    if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(ULONG_PTR)(address + 4), info + 4,
            count * 2, &copied) || copied != count * 2)
        return FALSE;
    for (index = 0; index < count;)
    {
        UINT offset = info[4 + index * 2];
        UINT operation = info[5 + index * 2] & 15;
        UINT operand = info[5 + index * 2] >> 4;
        UINT slots;
        BYTE mapped;
        if (offset == 0 || offset > info[1] || offset > previous)
            return FALSE;
        previous = offset;
        switch (operation)
        {
        case 0:
            if (!IsNonvolatileUnwindRegister(operand)) return FALSE;
            slots = 1;
            break;
        case 2: slots = 1; break;
        case 3:
            if (operand != 0 || frameRegister == 0) return FALSE;
            slots = 1;
            break;
        case 1:
            if (operand > 1) return FALSE;
            slots = operand == 0 ? 2 : 3;
            break;
        case 4: case 5:
            if (!IsNonvolatileUnwindRegister(operand)) return FALSE;
            slots = operation == 4 ? 2 : 3;
            break;
        case 8: case 9:
            if (operand < 6) return FALSE;
            slots = operation == 8 ? 2 : 3;
            break;
        default: return FALSE;
        }
        if (slots > count - index)
            return FALSE;
        if (offset <= ct->oldSize)
        {
            if (slots > MTH_UNWIND_CODE_SLOTS - output || !MapUnwindOffset(ct, offset, &mapped))
                return FALSE;
            memcpy(generated->info + 4 + output * 2, info + 4 + index * 2, slots * 2);
            generated->info[4 + output * 2] = mapped;
            output += slots;
            if (operation == 3) copiedFrame = TRUE;
        }
        index += slots;
    }
    if (output == 0)
        return TRUE; /* No copied stack/nonvolatile operation: leaf fallback remains valid. */
    if (!SupportsGeneratedUnwindV2())
        return FALSE;
    if (ct->oldSize > info[1])
    {
        for (index = 0; index < ct->nIP && ct->oldIPs[index] < ct->oldSize; ++index)
        {
            UINT start = ct->oldIPs[index];
            UINT end = index + 1 < ct->nIP ? ct->oldIPs[index + 1] : ct->oldSize;
            if (end > ct->oldSize) end = ct->oldSize;
            if ((start < info[1] && end > info[1]) ||
                (start >= info[1] && !MthInternal_IsUnwindNeutralInstruction(
                    (LPBYTE)ct->pTarget + start, end - start, frameRegister)))
                return FALSE;
        }
    }
    if (ct->newSize == 0 || ct->codeSize < ct->newSize || ct->codeSize > MEMORY_CODE_SIZE)
        return FALSE;
    generated->info[0] = 2;
    generated->info[1] = ct->codeSize;
    generated->info[2] = (BYTE)output;
    generated->info[3] = copiedFrame ? info[3] : 0;
    generated->functions[0].BeginAddress = 0;
    generated->functions[0].EndAddress = ct->codeSize;
    generated->functions[0].UnwindData = MEMORY_CODE_SIZE + (DWORD)offsetof(MTH_UNWIND_STORAGE, info);
    generated->count = 1;
#else
    (void)ct;
#endif
    return TRUE;
}

MTH_STATUS WINAPI MTH_CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal)
{
    MTH_STATUS status = MTH_OK;

    if (!EnterSpinLock())
        return MTH_ERROR_REENTRANT_CALL;

    if (g_hHeap != NULL && (g_shutdownPending || !RetryRetainedThreadOwnership()))
    {
        LeaveSpinLock();
        return MTH_ERROR_MEMORY_PROTECT;
    }

    if (g_hHeap != NULL)
    {
        if (MthInternal_IsExecutableAddress(pTarget) && MthInternal_IsExecutableAddress(pDetour))
        {
            UINT pos = FindHookEntry(pTarget);
            if (pos == INVALID_HOOK_POS)
            {
                LPVOID pBuffer = MthInternal_AllocateBuffer(pTarget);
                if (pBuffer != NULL)
                {
                    TRAMPOLINE ct;

                    ct.pTarget     = pTarget;
                    ct.pDetour     = pDetour;
                    ct.pTrampoline = pBuffer;
                    /* Every placement writes at least the short entry jump.
                     * Refuse that certain overlap before decoding owned patch
                     * bytes; check the complete placement after layout. */
                    if (IsPatchIntervalAvailable((ULONG_PTR)pTarget, sizeof(JMP_REL_SHORT)) &&
                        MthInternal_CreateTrampolineFunction(&ct) && IsHookPatchAvailable(&ct) &&
                        IsRelocationUnwindSafe(&ct))
                    {
                        PHOOK_ENTRY pHook = NULL;
                        if (MthInternal_RegisterBufferUnwind(pBuffer) &&
                            FlushInstructionCache(GetCurrentProcess(), pBuffer, MEMORY_SLOT_SIZE))
                            pHook = AddHookEntry();
                        else
                            status = MTH_ERROR_MEMORY_PROTECT;
                        if (pHook != NULL)
                        {
                            pHook->pTarget     = ct.pTarget;
#if defined(_M_X64) || defined(__x86_64__)
                            pHook->pDetour     = ct.pRelay;
#else
                            pHook->pDetour     = ct.pDetour;
#endif
                            pHook->pTrampoline = ct.pTrampoline;
                            pHook->patchAbove  = ct.patchAbove;
                            pHook->isEnabled   = FALSE;
                            pHook->queueEnable = FALSE;
                            pHook->nIP         = ct.nIP;
                            memcpy(pHook->oldIPs, ct.oldIPs, ARRAYSIZE(ct.oldIPs));
                            memcpy(pHook->newIPs, ct.newIPs, ARRAYSIZE(ct.newIPs));

                            // Back up the target function.

                            if (ct.patchAbove)
                            {
                                memcpy(
                                    pHook->backup,
                                    (LPBYTE)pTarget - sizeof(JMP_REL),
                                    sizeof(JMP_REL) + sizeof(JMP_REL_SHORT));
                            }
                            else
                            {
                                memcpy(pHook->backup, pTarget, sizeof(JMP_REL));
                            }

                            if (ppOriginal != NULL)
                                *ppOriginal = pHook->pTrampoline;
                        }
                        else
                        {
                            if (status == MTH_OK)
                            status = MTH_ERROR_MEMORY_ALLOC;
                        }
                    }
                    else
                    {
                        status = MTH_ERROR_UNSUPPORTED_FUNCTION;
                    }

                    if (status != MTH_OK)
                    {
if (!MthInternal_FreeBuffer(pBuffer))
                        {
                            g_retainedBuffer = pBuffer;
                            status = MTH_ERROR_MEMORY_PROTECT;
                        }
                    }
                }
                else
                {
                    status = MTH_ERROR_MEMORY_ALLOC;
                }
            }
            else
            {
                status = MTH_ERROR_ALREADY_CREATED;
            }
        }
        else
        {
            status = MTH_ERROR_NOT_EXECUTABLE;
        }
    }
    else
    {
        status = MTH_ERROR_NOT_INITIALIZED;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
MTH_STATUS WINAPI MTH_RemoveHook(LPVOID pTarget)
{
    MTH_STATUS status = MTH_OK;

    if (!EnterSpinLock())
        return MTH_ERROR_REENTRANT_CALL;

    if (g_hHeap != NULL && (g_shutdownPending || !RetryRetainedThreadOwnership()))
    {
        LeaveSpinLock();
        return MTH_ERROR_MEMORY_PROTECT;
    }

    if (g_hHeap != NULL)
    {
        UINT pos = FindHookEntry(pTarget);
        if (pos != INVALID_HOOK_POS)
        {
            if (g_hooks.pItems[pos].isEnabled)
            {
                FROZEN_THREADS threads;
                status = Freeze(&threads, pos, ACTION_DISABLE);
                if (status == MTH_OK)
                {
                    status = EnableHookLL(pos, FALSE);

                    status = FinishFreeze(&threads, status);
                }
            }

            if (status == MTH_OK)
            {
status = RetireHookEntry(pos);
            }
        }
        else
        {
            status = MTH_ERROR_NOT_CREATED;
        }
    }
    else
    {
        status = MTH_ERROR_NOT_INITIALIZED;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
static MTH_STATUS EnableHook(LPVOID pTarget, BOOL enable)
{
    MTH_STATUS status = MTH_OK;

    if (!EnterSpinLock())
        return MTH_ERROR_REENTRANT_CALL;

    if (g_hHeap != NULL && (g_shutdownPending || !RetryRetainedThreadOwnership()))
    {
        LeaveSpinLock();
        return MTH_ERROR_MEMORY_PROTECT;
    }

    if (g_hHeap != NULL)
    {
        if (pTarget == MTH_ALL_HOOKS)
        {
            status = EnableAllHooksLL(enable);
        }
        else
        {
            UINT pos = FindHookEntry(pTarget);
            if (pos != INVALID_HOOK_POS)
            {
                if (g_hooks.pItems[pos].isEnabled != enable)
                {
                    FROZEN_THREADS threads;
                    status = Freeze(&threads, pos, enable ? ACTION_ENABLE : ACTION_DISABLE);
                    if (status == MTH_OK)
                    {
                        status = EnableHookLL(pos, enable);

                        status = FinishFreeze(&threads, status);
                    }
                }
                else
                {
                    status = enable ? MTH_ERROR_ENABLED : MTH_ERROR_DISABLED;
                }
            }
            else
            {
                status = MTH_ERROR_NOT_CREATED;
            }
        }
    }
    else
    {
        status = MTH_ERROR_NOT_INITIALIZED;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
MTH_STATUS WINAPI MTH_EnableHook(LPVOID pTarget)
{
    return EnableHook(pTarget, TRUE);
}

//-------------------------------------------------------------------------
MTH_STATUS WINAPI MTH_DisableHook(LPVOID pTarget)
{
    return EnableHook(pTarget, FALSE);
}

//-------------------------------------------------------------------------
static MTH_STATUS QueueHook(LPVOID pTarget, BOOL queueEnable)
{
    MTH_STATUS status = MTH_OK;

    if (!EnterSpinLock())
        return MTH_ERROR_REENTRANT_CALL;

    if (g_hHeap != NULL && (g_shutdownPending || !RetryRetainedThreadOwnership()))
    {
        LeaveSpinLock();
        return MTH_ERROR_MEMORY_PROTECT;
    }

    if (g_hHeap != NULL)
    {
        if (pTarget == MTH_ALL_HOOKS)
        {
            UINT i;
            for (i = 0; i < g_hooks.size; ++i)
                g_hooks.pItems[i].queueEnable = queueEnable;
        }
        else
        {
            UINT pos = FindHookEntry(pTarget);
            if (pos != INVALID_HOOK_POS)
            {
                g_hooks.pItems[pos].queueEnable = queueEnable;
            }
            else
            {
                status = MTH_ERROR_NOT_CREATED;
            }
        }
    }
    else
    {
        status = MTH_ERROR_NOT_INITIALIZED;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
MTH_STATUS WINAPI MTH_QueueEnableHook(LPVOID pTarget)
{
    return QueueHook(pTarget, TRUE);
}

//-------------------------------------------------------------------------
MTH_STATUS WINAPI MTH_QueueDisableHook(LPVOID pTarget)
{
    return QueueHook(pTarget, FALSE);
}

//-------------------------------------------------------------------------
MTH_STATUS WINAPI MTH_ApplyQueued(VOID)
{
    MTH_STATUS status = MTH_OK;
    UINT i, first = INVALID_HOOK_POS;

    if (!EnterSpinLock())
        return MTH_ERROR_REENTRANT_CALL;

    if (g_hHeap != NULL && (g_shutdownPending || !RetryRetainedThreadOwnership()))
    {
        LeaveSpinLock();
        return MTH_ERROR_MEMORY_PROTECT;
    }

    if (g_hHeap != NULL)
    {
        for (i = 0; i < g_hooks.size; ++i)
        {
            if (g_hooks.pItems[i].isEnabled != g_hooks.pItems[i].queueEnable)
            {
                first = i;
                break;
            }
        }

        if (first != INVALID_HOOK_POS)
        {
            FROZEN_THREADS threads;
            status = Freeze(&threads, ALL_HOOKS_POS, ACTION_APPLY_QUEUED);
            if (status == MTH_OK)
            {
                for (i = first; i < g_hooks.size; ++i)
                {
                    PHOOK_ENTRY pHook = &g_hooks.pItems[i];
                    if (pHook->isEnabled != pHook->queueEnable)
                    {
                        status = EnableHookLL(i, pHook->queueEnable);
                        if (status != MTH_OK)
                            break;
                    }
                }

                status = FinishFreeze(&threads, status);
            }
        }
    }
    else
    {
        status = MTH_ERROR_NOT_INITIALIZED;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
MTH_STATUS WINAPI MTH_CreateHookApiEx(
    LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour,
    LPVOID *ppOriginal, LPVOID *ppTarget)
{
    HMODULE hModule;
    LPVOID  pTarget;

    if (MTH_IsOperationInProgressOnThisThread())
        return MTH_ERROR_REENTRANT_CALL;
    hModule = GetModuleHandleW(pszModule);
    if (hModule == NULL)
        return MTH_ERROR_MODULE_NOT_FOUND;

    pTarget = (LPVOID)GetProcAddress(hModule, pszProcName);
    if (pTarget == NULL)
        return MTH_ERROR_FUNCTION_NOT_FOUND;

    if (ppTarget != NULL)
        *ppTarget = pTarget;

    return MTH_CreateHook(pTarget, pDetour, ppOriginal);
}

//-------------------------------------------------------------------------
MTH_STATUS WINAPI MTH_CreateHookApi(
    LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, LPVOID *ppOriginal)
{
    return MTH_CreateHookApiEx(pszModule, pszProcName, pDetour, ppOriginal, NULL);
}

//-------------------------------------------------------------------------
const char *WINAPI MTH_StatusToString(MTH_STATUS status)
{
#define MTH_ST2STR(x)    \
    case x:             \
        return #x;

    switch (status) {
        MTH_ST2STR(MTH_UNKNOWN)
        MTH_ST2STR(MTH_OK)
        MTH_ST2STR(MTH_ERROR_REENTRANT_CALL)
        MTH_ST2STR(MTH_ERROR_ALREADY_INITIALIZED)
        MTH_ST2STR(MTH_ERROR_NOT_INITIALIZED)
        MTH_ST2STR(MTH_ERROR_ALREADY_CREATED)
        MTH_ST2STR(MTH_ERROR_NOT_CREATED)
        MTH_ST2STR(MTH_ERROR_ENABLED)
        MTH_ST2STR(MTH_ERROR_DISABLED)
        MTH_ST2STR(MTH_ERROR_NOT_EXECUTABLE)
        MTH_ST2STR(MTH_ERROR_UNSUPPORTED_FUNCTION)
        MTH_ST2STR(MTH_ERROR_MEMORY_ALLOC)
        MTH_ST2STR(MTH_ERROR_MEMORY_PROTECT)
        MTH_ST2STR(MTH_ERROR_MODULE_NOT_FOUND)
        MTH_ST2STR(MTH_ERROR_FUNCTION_NOT_FOUND)
    }

#undef MTH_ST2STR

    return "(unknown)";
}

//-------------------------------------------------------------------------
BOOL WINAPI MTH_IsOperationInProgressOnThisThread(VOID)
{
    return (DWORD)InterlockedCompareExchange(&g_ownerThreadId, 0, 0) == GetCurrentThreadId();
}
