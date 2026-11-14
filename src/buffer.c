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

#include <windows.h>
#include "buffer.h"

// Size of each memory block. (= page size of VirtualAlloc)
#define MEMORY_BLOCK_SIZE 0x1000
#define MEMORY_BLOCK_SLOTS (MEMORY_BLOCK_SIZE / MEMORY_SLOT_SIZE)
#define MEMORY_SLOT_WORDS ((MEMORY_BLOCK_SLOTS + 31) / 32)

// Max range for seeking a memory block. (= 1024MB)
#define MAX_MEMORY_RANGE 0x40000000

// Memory protection flags to check the executable address.
#define PAGE_EXECUTE_FLAGS \
    (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

// Memory slot.
typedef struct _MEMORY_SLOT
{
    union
    {
        struct _MEMORY_SLOT *pNext;
        UINT8 buffer[MEMORY_SLOT_SIZE];
    };
} MEMORY_SLOT, *PMEMORY_SLOT;

// Memory block info. Placed at the head of each block.
typedef struct _MEMORY_BLOCK
{
    struct _MEMORY_BLOCK *pNext;
    PMEMORY_SLOT pFree;         // First element of the free slot list.
    UINT usedCount;
    /* Live slot ownership, independent of executable bytes and the free list.
     * Bit zero (the allocator header) is never a published trampoline. */
    UINT32 allocated[MEMORY_SLOT_WORDS];
} MEMORY_BLOCK, *PMEMORY_BLOCK;
typedef char MTH_BLOCK_HEADER_FITS[(sizeof(MEMORY_BLOCK) <= MEMORY_SLOT_SIZE) ? 1 : -1];

//-------------------------------------------------------------------------
// Global Variables:
//-------------------------------------------------------------------------

// First element of the memory block list.
static PMEMORY_BLOCK g_pMemoryBlocks;

BOOL MthInternal_RegisterBufferUnwind(LPVOID pBuffer)
{
#if defined(_M_X64) || defined(__x86_64__)
    PMTH_UNWIND_STORAGE unwind = MTH_BUFFER_UNWIND(pBuffer);
    if (unwind->count == 0 || unwind->registered)
        return TRUE;
    if (!RtlAddFunctionTable(unwind->functions, unwind->count, (DWORD64)(ULONG_PTR)pBuffer))
        return FALSE;
    unwind->registered = TRUE;
    unwind->restorePending = FALSE;
#else
    (void)pBuffer;
#endif
    return TRUE;
}

static BOOL UnregisterSlotUnwind(LPVOID pBuffer)
{
#if defined(_M_X64) || defined(__x86_64__)
    PMTH_UNWIND_STORAGE unwind = MTH_BUFFER_UNWIND(pBuffer);
    if (unwind->registered)
    {
        if (!RtlDeleteFunctionTable(unwind->functions))
            return FALSE;
        unwind->registered = FALSE;
        /* If memory release later fails, restore the published table before
         * the consumer may reopen admission to the retained trampoline. */
        unwind->restorePending = TRUE;
    }
#else
    (void)pBuffer;
#endif
    return TRUE;
}

BOOL MthInternal_RetryBufferUnwind(VOID)
{
#if defined(_M_X64) || defined(__x86_64__)
    PMEMORY_BLOCK block;
    BOOL complete = TRUE;
    for (block = g_pMemoryBlocks; block != NULL; block = block->pNext)
    {
        PMEMORY_SLOT slot = (PMEMORY_SLOT)block + 1;
        for (; (ULONG_PTR)slot - (ULONG_PTR)block <= MEMORY_BLOCK_SIZE - MEMORY_SLOT_SIZE; ++slot)
            if (MTH_BUFFER_UNWIND(slot)->restorePending && !MthInternal_RegisterBufferUnwind(slot))
                complete = FALSE;
    }
    return complete;
#else
    return TRUE;
#endif
}

BOOL MthInternal_HasPendingBufferUnwind(VOID)
{
#if defined(_M_X64) || defined(__x86_64__)
    PMEMORY_BLOCK block;
    for (block = g_pMemoryBlocks; block != NULL; block = block->pNext)
    {
        PMEMORY_SLOT slot = (PMEMORY_SLOT)block + 1;
        for (; (ULONG_PTR)slot - (ULONG_PTR)block <= MEMORY_BLOCK_SIZE - MEMORY_SLOT_SIZE; ++slot)
            if (MTH_BUFFER_UNWIND(slot)->restorePending)
                return TRUE;
    }
#endif
    return FALSE;
}

static BOOL UnregisterBlockUnwind(PMEMORY_BLOCK block)
{
    PMEMORY_SLOT slot = (PMEMORY_SLOT)block + 1;
    for (; (ULONG_PTR)slot - (ULONG_PTR)block <= MEMORY_BLOCK_SIZE - MEMORY_SLOT_SIZE; ++slot)
        if (!UnregisterSlotUnwind(slot))
            return FALSE;
    return TRUE;
}

//-------------------------------------------------------------------------
VOID MthInternal_InitializeBuffer(VOID)
{
    // Nothing to do for now.
}

//-------------------------------------------------------------------------
BOOL MthInternal_UninitializeBuffer(VOID)
{
    while (g_pMemoryBlocks != NULL)
    {
        PMEMORY_BLOCK block = g_pMemoryBlocks;
        PMEMORY_BLOCK next = block->pNext;
        if (!UnregisterBlockUnwind(block) || !VirtualFree(block, 0, MEM_RELEASE))
        {
            (void)MthInternal_RetryBufferUnwind();
            return FALSE;
        }
        g_pMemoryBlocks = next;
    }
    return TRUE;
}

BOOL MthInternal_IsBufferAddress(ULONG_PTR address)
{
    PMEMORY_BLOCK block;
    for (block = g_pMemoryBlocks; block != NULL; block = block->pNext)
        if (address >= (ULONG_PTR)block && address - (ULONG_PTR)block < MEMORY_BLOCK_SIZE)
        {
            UINT index = (UINT)((address - (ULONG_PTR)block) / MEMORY_SLOT_SIZE);
            /* Retain every byte of an occupied code/metadata slot. Unused
             * slots and allocator bookkeeping cannot hold a published entry. */
            return (block->allocated[index / 32] & ((UINT32)1 << (index % 32))) != 0;
        }
    return FALSE;
}

//-------------------------------------------------------------------------
#if defined(_M_X64) || defined(__x86_64__)
static LPVOID FindPrevFreeRegion(LPVOID pAddress, LPVOID pMinAddr, DWORD dwAllocationGranularity)
{
    ULONG_PTR tryAddr = (ULONG_PTR)pAddress;

    // Round down to the allocation granularity.
    tryAddr -= tryAddr % dwAllocationGranularity;

    // Start from the previous allocation granularity multiply.
    tryAddr -= dwAllocationGranularity;

    while (tryAddr >= (ULONG_PTR)pMinAddr)
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPVOID)tryAddr, &mbi, sizeof(mbi)) == 0)
            break;

        if (mbi.State == MEM_FREE)
            return (LPVOID)tryAddr;

        if ((ULONG_PTR)mbi.AllocationBase < dwAllocationGranularity)
            break;

        tryAddr = (ULONG_PTR)mbi.AllocationBase - dwAllocationGranularity;
    }

    return NULL;
}
#endif

//-------------------------------------------------------------------------
#if defined(_M_X64) || defined(__x86_64__)
static LPVOID FindNextFreeRegion(LPVOID pAddress, LPVOID pMaxAddr, DWORD dwAllocationGranularity)
{
    ULONG_PTR tryAddr = (ULONG_PTR)pAddress;

    // Round down to the allocation granularity.
    tryAddr -= tryAddr % dwAllocationGranularity;

    // Start from the next allocation granularity multiply.
    tryAddr += dwAllocationGranularity;

    while (tryAddr <= (ULONG_PTR)pMaxAddr)
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPVOID)tryAddr, &mbi, sizeof(mbi)) == 0)
            break;

        if (mbi.State == MEM_FREE)
            return (LPVOID)tryAddr;

        tryAddr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;

        // Round up to the next allocation granularity.
        tryAddr += dwAllocationGranularity - 1;
        tryAddr -= tryAddr % dwAllocationGranularity;
    }

    return NULL;
}
#endif

//-------------------------------------------------------------------------
static PMEMORY_BLOCK GetMemoryBlock(LPVOID pOrigin)
{
    PMEMORY_BLOCK pBlock;
#if defined(_M_X64) || defined(__x86_64__)
    ULONG_PTR minAddr;
    ULONG_PTR maxAddr;

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    minAddr = (ULONG_PTR)si.lpMinimumApplicationAddress;
    maxAddr = (ULONG_PTR)si.lpMaximumApplicationAddress;

    // pOrigin ± 512MB
    if ((ULONG_PTR)pOrigin > MAX_MEMORY_RANGE && minAddr < (ULONG_PTR)pOrigin - MAX_MEMORY_RANGE)
        minAddr = (ULONG_PTR)pOrigin - MAX_MEMORY_RANGE;

    if (maxAddr > (ULONG_PTR)pOrigin + MAX_MEMORY_RANGE)
        maxAddr = (ULONG_PTR)pOrigin + MAX_MEMORY_RANGE;

    // Make room for MEMORY_BLOCK_SIZE bytes.
    maxAddr -= MEMORY_BLOCK_SIZE - 1;
#endif

    // Look the registered blocks for a reachable one.
    for (pBlock = g_pMemoryBlocks; pBlock != NULL; pBlock = pBlock->pNext)
    {
#if defined(_M_X64) || defined(__x86_64__)
        // Ignore the blocks too far.
        if ((ULONG_PTR)pBlock < minAddr || (ULONG_PTR)pBlock >= maxAddr)
            continue;
#endif
        // The block has at least one unused slot.
        if (pBlock->pFree != NULL)
            return pBlock;
    }

#if defined(_M_X64) || defined(__x86_64__)
    // Alloc a new block above if not found.
    {
        LPVOID pAlloc = pOrigin;
        while ((ULONG_PTR)pAlloc >= minAddr)
        {
            pAlloc = FindPrevFreeRegion(pAlloc, (LPVOID)minAddr, si.dwAllocationGranularity);
            if (pAlloc == NULL)
                break;

            pBlock = (PMEMORY_BLOCK)VirtualAlloc(
                pAlloc, MEMORY_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (pBlock != NULL)
                break;
        }
    }

    // Alloc a new block below if not found.
    if (pBlock == NULL)
    {
        LPVOID pAlloc = pOrigin;
        while ((ULONG_PTR)pAlloc <= maxAddr)
        {
            pAlloc = FindNextFreeRegion(pAlloc, (LPVOID)maxAddr, si.dwAllocationGranularity);
            if (pAlloc == NULL)
                break;

            pBlock = (PMEMORY_BLOCK)VirtualAlloc(
                pAlloc, MEMORY_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (pBlock != NULL)
                break;
        }
    }
#else
    // In x86 mode, a memory block can be placed anywhere.
    pBlock = (PMEMORY_BLOCK)VirtualAlloc(
        NULL, MEMORY_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#endif

    if (pBlock != NULL)
    {
        // Build a linked list of all the slots.
        PMEMORY_SLOT pSlot = (PMEMORY_SLOT)pBlock + 1;
        pBlock->pFree = NULL;
        pBlock->usedCount = 0;
        memset(pBlock->allocated, 0, sizeof(pBlock->allocated));
        do
        {
            pSlot->pNext = pBlock->pFree;
            pBlock->pFree = pSlot;
            pSlot++;
        } while ((ULONG_PTR)pSlot - (ULONG_PTR)pBlock <= MEMORY_BLOCK_SIZE - MEMORY_SLOT_SIZE);

        pBlock->pNext = g_pMemoryBlocks;
        g_pMemoryBlocks = pBlock;
    }

    return pBlock;
}

//-------------------------------------------------------------------------
LPVOID MthInternal_AllocateBuffer(LPVOID pOrigin)
{
    PMEMORY_SLOT  pSlot;
    PMEMORY_BLOCK pBlock = GetMemoryBlock(pOrigin);
    if (pBlock == NULL)
        return NULL;

    // Remove an unused slot from the list.
    pSlot = pBlock->pFree;
    pBlock->pFree = pSlot->pNext;
    pBlock->usedCount++;
    {
        UINT index = (UINT)(((ULONG_PTR)pSlot - (ULONG_PTR)pBlock) / MEMORY_SLOT_SIZE);
        pBlock->allocated[index / 32] |= (UINT32)1 << (index % 32);
    }
#ifdef _DEBUG
    // Fill the slot with INT3 for debugging.
    memset(pSlot, 0xCC, sizeof(MEMORY_SLOT));
#endif
#if defined(_M_X64) || defined(__x86_64__)
    memset(MTH_BUFFER_UNWIND(pSlot), 0, sizeof(MTH_UNWIND_STORAGE));
#endif
    return pSlot;
}

//-------------------------------------------------------------------------
BOOL MthInternal_FreeBuffer(LPVOID pBuffer)
{
    PMEMORY_BLOCK block = g_pMemoryBlocks, previous = NULL;
    ULONG_PTR target = (ULONG_PTR)pBuffer / MEMORY_BLOCK_SIZE * MEMORY_BLOCK_SIZE;
    while (block != NULL)
    {
        if ((ULONG_PTR)block == target)
        {
            if ((ULONG_PTR)pBuffer < (ULONG_PTR)block + MEMORY_SLOT_SIZE ||
                ((ULONG_PTR)pBuffer - (ULONG_PTR)block) % MEMORY_SLOT_SIZE != 0)
                return FALSE;
            {
                UINT index = (UINT)(((ULONG_PTR)pBuffer - (ULONG_PTR)block) / MEMORY_SLOT_SIZE);
                if (!(block->allocated[index / 32] & ((UINT32)1 << (index % 32))))
                    return FALSE;
            }
            if (!UnregisterSlotUnwind(pBuffer))
                return FALSE;
            if (block->usedCount == 1)
            {
                PMEMORY_BLOCK next = block->pNext;
                if (!VirtualFree(block, 0, MEM_RELEASE))
                {
                    (void)MthInternal_RetryBufferUnwind();
                    return FALSE;
                }
                if (previous != NULL) previous->pNext = next;
                else g_pMemoryBlocks = next;
            }
            else
            {
                PMEMORY_SLOT slot = (PMEMORY_SLOT)pBuffer;
                UINT index = (UINT)(((ULONG_PTR)pBuffer - (ULONG_PTR)block) / MEMORY_SLOT_SIZE);
                block->allocated[index / 32] &= ~((UINT32)1 << (index % 32));
#ifdef _DEBUG
                memset(slot, 0, sizeof(MEMORY_SLOT));
#endif
#if defined(_M_X64) || defined(__x86_64__)
                memset(MTH_BUFFER_UNWIND(slot), 0, sizeof(MTH_UNWIND_STORAGE));
#endif
                slot->pNext = block->pFree;
                block->pFree = slot;
                --block->usedCount;
            }
            return TRUE;
        }
        previous = block;
        block = block->pNext;
    }
    return FALSE;
}

//-------------------------------------------------------------------------
BOOL MthInternal_IsExecutableAddress(LPVOID pAddress)
{
    MEMORY_BASIC_INFORMATION mi;
    return VirtualQuery(pAddress, &mi, sizeof(mi)) && mi.State == MEM_COMMIT &&
           (mi.Protect & PAGE_EXECUTE_FLAGS) &&
           !(mi.Protect & (PAGE_GUARD | PAGE_NOACCESS));
}
