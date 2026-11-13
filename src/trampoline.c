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

/* MithrilHook relocation hardening adapted from Citrine PR #363.
 * Modifications: SPDX-License-Identifier: GPL-3.0-only
 * Original MinHook copyright and BSD terms above are retained. */
#include <windows.h>

#include <string.h>

#ifndef ARRAYSIZE
    #define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif

#if defined(_M_X64) || defined(__x86_64__)
    #include "./hde/hde64.h"
    typedef hde64s HDE;
    #define HDE_DISASM(code, hs) MthInternal_hde64_disasm(code, hs)
#else
    #include "./hde/hde32.h"
    typedef hde32s HDE;
    #define HDE_DISASM(code, hs) MthInternal_hde32_disasm(code, hs)
#endif

#include "trampoline.h"
#include "buffer.h"

// Maximum size of a trampoline function.
#if defined(_M_X64) || defined(__x86_64__)
    #define TRAMPOLINE_MAX_SIZE (MEMORY_CODE_SIZE - sizeof(JMP_ABS))
#else
    #define TRAMPOLINE_MAX_SIZE MEMORY_CODE_SIZE
#endif

//-------------------------------------------------------------------------
static BOOL IsReadableProtection(DWORD protect)
{
    if (protect & (PAGE_GUARD | PAGE_NOACCESS))
        return FALSE;

    switch (protect & 0xFF)
    {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return TRUE;
    default:
        return FALSE;
    }
}

//-------------------------------------------------------------------------
static SIZE_T CopyReadableCode(LPBYTE pBuffer, LPCVOID pAddress, SIZE_T size)
{
    ULONG_PTR cursor = (ULONG_PTR)pAddress;
    SIZE_T copied = 0;

    if (size == 0 || cursor + size < cursor)
        return 0;

    while (copied < size)
    {
        MEMORY_BASIC_INFORMATION mi;
        ULONG_PTR regionEnd;
        SIZE_T available;
        SIZE_T transferred;

        if (!VirtualQuery((LPCVOID)cursor, &mi, sizeof(mi))
            || mi.State != MEM_COMMIT
            || !IsReadableProtection(mi.Protect))
        {
            break;
        }

        regionEnd = (ULONG_PTR)mi.BaseAddress + mi.RegionSize;
        if (regionEnd <= cursor)
            break;

        available = regionEnd - cursor;
        if (available > size - copied)
            available = size - copied;

        if (!ReadProcessMemory(
                GetCurrentProcess(),
                (LPCVOID)cursor,
                pBuffer + copied,
                available,
                &transferred)
            || transferred != available)
        {
            break;
        }
        cursor += available;
        copied += available;
    }

    return copied;
}

//-------------------------------------------------------------------------
static BOOL IsCodePadding(LPBYTE pInst, UINT size)
{
    UINT8 buffer[sizeof(JMP_REL)];
    UINT i;

    if (size == 0 || size > sizeof(buffer)
        || CopyReadableCode(buffer, pInst, size) != size
        || (buffer[0] != 0x00 && buffer[0] != 0x90 && buffer[0] != 0xCC))
    {
        return FALSE;
    }

    for (i = 1; i < size; ++i)
    {
        if (buffer[i] != buffer[0])
            return FALSE;
    }
    return TRUE;
}

#if defined(_M_X64) || defined(__x86_64__)
static UINT NormalizeUnwindRegister(UINT reg, BOOL byteOperand, BYTE rex)
{
    /* Without REX, byte encodings 4..7 are AH/CH/DH/BH, not SP/BP/SI/DI. */
    return byteOperand && rex == 0 && reg >= 4 && reg < 8 ? reg - 4 : reg;
}

static BOOL IsUnwindRegisterProtected(UINT reg, UINT frameRegister)
{
    return reg == 4 || (frameRegister != 0 && reg == frameRegister);
}
#endif

/* Body instructions copied after a short prologue must not change the stack or
 * active frame register. Unknown forms are refused rather than misdescribed by
 * prologue metadata; the whitelist is deliberately narrower than the decoder. */
BOOL MthInternal_IsUnwindNeutralInstruction(LPCVOID address, UINT length, UINT frameRegister)
{
#if defined(_M_X64) || defined(__x86_64__)
    BYTE bytes[16] = {0};
    HDE hs;
    UINT op, reg, rm;
    BOOL byteOperand;
    SIZE_T readable = CopyReadableCode(bytes, address, sizeof(bytes));
    if (readable < length || HDE_DISASM(bytes, &hs) != length ||
        (hs.flags & (F_ERROR | F_PREFIX_REX2)))
        return FALSE;
    op = hs.opcode;
    byteOperand = (op >= 0xb0 && op <= 0xb7) || op == 0x88 || op == 0x8a ||
        op == 0x86 || op == 0xc6 || op == 0xc0 || op == 0xd0 || op == 0xd2 ||
        op == 0xfe || op == 0xf6 || op == 0x80 ||
        (op <= 0x3b && (op & 7) <= 3 && (op & 1) == 0) ||
        (op == 0x0f && hs.opcode2 >= 0x90 && hs.opcode2 <= 0x9f);
    reg = NormalizeUnwindRegister(hs.modrm_reg + (hs.rex_r ? 8 : 0), byteOperand, hs.rex);
    rm = NormalizeUnwindRegister(hs.modrm_rm + (hs.rex_b ? 8 : 0), byteOperand, hs.rex);
    if (op == 0xe8 || op == 0xe9 || op == 0xeb || (op >= 0x70 && op <= 0x7f) ||
        (op >= 0xe0 && op <= 0xe3) || op == 0x84 || op == 0x85 || op == 0xa8 || op == 0xa9)
        return TRUE;
    if (op >= 0x90 && op <= 0x97)
        return !IsUnwindRegisterProtected(0, frameRegister) &&
            !IsUnwindRegisterProtected((op & 7) + (hs.rex_b ? 8 : 0), frameRegister);
    if (op >= 0xb0 && op <= 0xbf)
        return !IsUnwindRegisterProtected(NormalizeUnwindRegister(
            (op & 7) + (hs.rex_b ? 8 : 0), op <= 0xb7, hs.rex), frameRegister);
    if (op == 0x8a || op == 0x8b || op == 0x8d || op == 0x63 || op == 0x69 || op == 0x6b)
        return !IsUnwindRegisterProtected(reg, frameRegister);
    if (op == 0x88 || op == 0x89 || op == 0xc6 || op == 0xc7 ||
        op == 0xc0 || op == 0xc1 || (op >= 0xd0 && op <= 0xd3) || op == 0xfe)
        return hs.modrm_mod != 3 || !IsUnwindRegisterProtected(rm, frameRegister);
    if (op == 0x86 || op == 0x87)
        return !IsUnwindRegisterProtected(reg, frameRegister) &&
            (hs.modrm_mod != 3 || !IsUnwindRegisterProtected(rm, frameRegister));
    if (op <= 0x3d && (op & 7) <= 5)
    {
        if (op >= 0x38) return TRUE; /* CMP. */
        if ((op & 7) >= 4) return !IsUnwindRegisterProtected(0, frameRegister);
        return (op & 2) ? !IsUnwindRegisterProtected(reg, frameRegister) :
            (hs.modrm_mod != 3 || !IsUnwindRegisterProtected(rm, frameRegister));
    }
    if (op == 0x80 || op == 0x81 || op == 0x83)
        return hs.modrm_reg == 7 || hs.modrm_mod != 3 || !IsUnwindRegisterProtected(rm, frameRegister);
    if (op == 0xf6 || op == 0xf7)
        return hs.modrm_reg == 0 || hs.modrm_reg >= 4 ||
            ((hs.modrm_reg == 2 || hs.modrm_reg == 3) &&
             (hs.modrm_mod != 3 || !IsUnwindRegisterProtected(rm, frameRegister)));
    if (op == 0xff)
        return hs.modrm_reg == 2 || hs.modrm_reg == 4 ||
            ((hs.modrm_reg == 0 || hs.modrm_reg == 1) &&
             (hs.modrm_mod != 3 || !IsUnwindRegisterProtected(rm, frameRegister)));
    if (op == 0x0f)
    {
        if ((hs.opcode2 >= 0x80 && hs.opcode2 <= 0x8f) || hs.opcode2 == 0x1f ||
            (hs.opcode2 == 0x1e && hs.p_rep == 0xf3 && hs.modrm == 0xfa)) return TRUE;
        if ((hs.opcode2 >= 0x40 && hs.opcode2 <= 0x4f) || hs.opcode2 == 0xaf ||
            hs.opcode2 == 0xb6 || hs.opcode2 == 0xb7 || hs.opcode2 == 0xbe || hs.opcode2 == 0xbf)
            return !IsUnwindRegisterProtected(reg, frameRegister);
        if (hs.opcode2 >= 0x90 && hs.opcode2 <= 0x9f)
            return hs.modrm_mod != 3 || !IsUnwindRegisterProtected(rm, frameRegister);
    }
    return FALSE;
#else
    (void)address; (void)length; (void)frameRegister;
    return TRUE;
#endif
}

//-------------------------------------------------------------------------
BOOL MthInternal_CreateTrampolineFunction(PTRAMPOLINE ct)
{
#if defined(_M_X64) || defined(__x86_64__)
    CALL_ABS call = {
        0xFF, 0x15, 0x00000002, // FF15 00000002: CALL [RIP+8]
        0xEB, 0x08,             // EB 08:         JMP +10
        0x0000000000000000ULL   // Absolute destination address
    };
    JMP_ABS jmp = {
        0xFF, 0x25, 0x00000000, // FF25 00000000: JMP [RIP+6]
        0x0000000000000000ULL   // Absolute destination address
    };
    JCC_ABS jcc = {
        0x70, 0x0E,             // 7* 0E:         J** +16
        0xFF, 0x25, 0x00000000, // FF25 00000000: JMP [RIP+6]
        0x0000000000000000ULL   // Absolute destination address
    };
#else
    CALL_REL call = {
        0xE8,                   // E8 xxxxxxxx: CALL +5+xxxxxxxx
        0x00000000              // Relative destination address
    };
    JMP_REL jmp = {
        0xE9,                   // E9 xxxxxxxx: JMP +5+xxxxxxxx
        0x00000000              // Relative destination address
    };
    JCC_REL jcc = {
        0x0F, 0x80,             // 0F8* xxxxxxxx: J** +6+xxxxxxxx
        0x00000000              // Relative destination address
    };
#endif

    UINT8     oldPos   = 0;
    UINT8     newPos   = 0;
    struct
    {
        UINT8 oldTarget;
        UINT8 newEnd;
        UINT8 displacement;
        UINT8 width;
    } internalBranches[ARRAYSIZE(ct->oldIPs)];
    UINT internalCount = 0;
    ULONG_PTR jmpDest  = 0;     // Destination address of an internal jump.
    BOOL      finished = FALSE; // Is the function completed?
    UINT8     instBuf[16];

    ct->patchAbove = FALSE;
    ct->nIP        = 0;
    ct->oldSize    = 0;
    ct->newSize    = 0;

    do
    {
        HDE       hs;
        UINT      copySize;
        LPVOID    pCopySrc;
        BOOL      internalBranch = FALSE;
        UINT8     internalTarget = 0;
        ULONG_PTR pOldInst = (ULONG_PTR)ct->pTarget     + oldPos;
        ULONG_PTR pNewInst = (ULONG_PTR)ct->pTrampoline + newPos;

        SIZE_T    readableSize;

        memset(instBuf, 0, sizeof(instBuf));
        readableSize = CopyReadableCode(instBuf, (LPCVOID)pOldInst, sizeof(instBuf));
        if (readableSize == 0)
            return FALSE;

        copySize = HDE_DISASM(instBuf, &hs);
        if ((hs.flags & F_ERROR) || copySize > readableSize)
            return FALSE;

        /* HDE's 66-prefixed near displacement width is insufficient to model
         * vendor/mode-specific destination semantics. Refuse before copying;
         * a successful trampoline must never silently branch to another IP. */
        if (oldPos < sizeof(JMP_REL) && hs.p_66 && (hs.opcode == 0xe8 || hs.opcode == 0xe9 ||
            (hs.opcode == 0x0f && hs.opcode2 >= 0x80 && hs.opcode2 <= 0x8f)))
            return FALSE;

        if (oldPos < sizeof(JMP_REL))
        {
#if defined(_M_X64) || defined(__x86_64__)
            /* The decoder recognizes REX2 lengths, but the engine has no full
             * APX register/unwind contract. Never infer one from legacy REX. */
            if (hs.flags & F_PREFIX_REX2)
                return FALSE;
#endif
            /* A call-next can expose its return address as data (get-PC).
             * Rewriting the CALL changes that value; PUSH/JMP emulation would
             * also violate shadow-stack contracts. Refuse this known idiom. */
            if (hs.opcode == 0xe8 && hs.imm.imm32 == 0)
                return FALSE;
        }

        pCopySrc = instBuf;
        if (oldPos >= sizeof(JMP_REL))
        {
            // The trampoline function is long enough.
            // Complete the function with the jump to the target function.
#if defined(_M_X64) || defined(__x86_64__)
            jmp.address = pOldInst;
#else
            jmp.operand = (INT32)(pOldInst - (pNewInst + sizeof(jmp)));
#endif
            pCopySrc = &jmp;
            copySize = sizeof(jmp);

            finished = TRUE;
        }
#if defined(_M_X64) || defined(__x86_64__)
        else if ((hs.modrm & 0xC7) == 0x05)
        {
            // Instructions using RIP relative addressing. (ModR/M = 00???101B)

            // Modify the RIP relative address.
            LPBYTE pRelAddr;
            UINT32 displacement;

            // Relative address is stored at (instruction length - immediate value length - 4).
            pRelAddr = (LPBYTE)(instBuf + hs.len - ((hs.flags & 0x3C) >> 2) - 4);
            if (hs.flags & F_PREFIX_67)
            {
                // EIP-relative addressing wraps at 32 bits in 64-bit mode.
                displacement = (UINT32)(
                    (pOldInst + hs.len + (INT32)hs.disp.disp32)
                    - (pNewInst + hs.len));
            }
            else
            {
                INT64 absoluteAddress = (INT64)pOldInst + hs.len + (INT32)hs.disp.disp32;
                INT64 newDisplacement = absoluteAddress - ((INT64)pNewInst + hs.len);

                if (newDisplacement < (-2147483647LL - 1)
                    || newDisplacement > 2147483647LL)
                {
                    return FALSE;
                }
                displacement = (UINT32)(INT32)newDisplacement;
            }

            memcpy(pRelAddr, &displacement, sizeof(displacement));

            // Complete the function if JMP (FF /4).
            if (hs.opcode == 0xFF && hs.modrm_reg == 4)
                finished = TRUE;
        }
#endif
        else if (hs.opcode == 0xE8)
        {
            // Direct relative CALL
            ULONG_PTR dest = pOldInst + hs.len + (INT32)hs.imm.imm32;
#if defined(_M_X64) || defined(__x86_64__)
            call.address = dest;
#else
            call.operand = (INT32)(dest - (pNewInst + sizeof(call)));
#endif
            pCopySrc = &call;
            copySize = sizeof(call);
        }
        else if ((hs.opcode & 0xFD) == 0xE9)
        {
            // Direct relative JMP (EB or E9)
            ULONG_PTR dest = pOldInst + hs.len;

            if (hs.opcode == 0xEB) // isShort jmp
                dest += (INT8)hs.imm.imm8;
            else
                dest += (INT32)hs.imm.imm32;

            // Simply copy an internal jump.
            if ((ULONG_PTR)ct->pTarget <= dest
                && dest < ((ULONG_PTR)ct->pTarget + sizeof(JMP_REL)))
            {
                internalBranch = TRUE;
                internalTarget = (UINT8)(dest - (ULONG_PTR)ct->pTarget);
                if (jmpDest < dest)
                    jmpDest = dest;
            }
            else
            {
#if defined(_M_X64) || defined(__x86_64__)
                jmp.address = dest;
#else
                jmp.operand = (INT32)(dest - (pNewInst + sizeof(jmp)));
#endif
                pCopySrc = &jmp;
                copySize = sizeof(jmp);

                // Exit the function if it is not in the branch.
                finished = (pOldInst >= jmpDest);
            }
        }
        else if ((hs.opcode & 0xF0) == 0x70
            || (hs.opcode & 0xFC) == 0xE0
            || (hs.opcode == 0x0F && (hs.opcode2 & 0xF0) == 0x80))
        {
            // Direct relative Jcc
            ULONG_PTR dest = pOldInst + hs.len;

            if ((hs.opcode & 0xF0) == 0x70      // Jcc
                || (hs.opcode & 0xFC) == 0xE0)  // LOOPNZ/LOOPZ/LOOP/JECXZ
                dest += (INT8)hs.imm.imm8;
            else
                dest += (INT32)hs.imm.imm32;

            // Simply copy an internal jump.
            if ((ULONG_PTR)ct->pTarget <= dest
                && dest < ((ULONG_PTR)ct->pTarget + sizeof(JMP_REL)))
            {
                internalBranch = TRUE;
                internalTarget = (UINT8)(dest - (ULONG_PTR)ct->pTarget);
                if (jmpDest < dest)
                    jmpDest = dest;
            }
            else if ((hs.opcode & 0xFC) == 0xE0)
            {
                // LOOPNZ/LOOPZ/LOOP/JCXZ/JECXZ to the outside are not supported.
                return FALSE;
            }
            else
            {
                UINT8 cond = ((hs.opcode != 0x0F ? hs.opcode : hs.opcode2) & 0x0F);
#if defined(_M_X64) || defined(__x86_64__)
                // Invert the condition in x64 mode to simplify the conditional jump logic.
                jcc.opcode  = 0x71 ^ cond;
                jcc.address = dest;
#else
                jcc.opcode1 = 0x80 | cond;
                jcc.operand = (INT32)(dest - (pNewInst + sizeof(jcc)));
#endif
                pCopySrc = &jcc;
                copySize = sizeof(jcc);
            }
        }
        else if ((hs.opcode & 0xFE) == 0xC2)
        {
            // RET (C2 or C3)

            // Complete the function if not in a branch.
            finished = (pOldInst >= jmpDest);
        }
        else if (hs.flags & F_RELATIVE)
        {
            // Never copy an unhandled PC-relative instruction (e.g. XBEGIN)
            // with its original displacement into a different code address.
            return FALSE;
        }

        // Can't alter the instruction length in a branch.
        if (pOldInst < jmpDest && copySize != hs.len)
            return FALSE;

        // Trampoline function is too large.
        if ((newPos + copySize) > TRAMPOLINE_MAX_SIZE)
            return FALSE;

        // Trampoline function has too many instructions.
        if (ct->nIP >= ARRAYSIZE(ct->oldIPs))
            return FALSE;

        if (internalBranch)
        {
            UINT8 width = (hs.flags & F_IMM8) ? 1 : 4;
            /* Resolve only after every copied instruction boundary is known.
             * A prior expansion can invalidate an unchanged backward offset. */
            if (internalCount >= ARRAYSIZE(internalBranches) || copySize != hs.len || hs.len < width)
                return FALSE;
            internalBranches[internalCount].oldTarget = internalTarget;
            internalBranches[internalCount].newEnd = (UINT8)(newPos + hs.len);
            internalBranches[internalCount].displacement = (UINT8)(newPos + hs.len - width);
            internalBranches[internalCount].width = width;
            ++internalCount;
        }

        ct->oldIPs[ct->nIP] = oldPos;
        ct->newIPs[ct->nIP] = newPos;
        ct->nIP++;

        // Avoid using memcpy to reduce the footprint.
        memcpy((LPBYTE)ct->pTrampoline + newPos, pCopySrc, copySize);
        if (oldPos < sizeof(JMP_REL))
        {
            ct->oldSize = oldPos + hs.len;
            ct->newSize = newPos + copySize;
        }
        newPos += copySize;
        oldPos += hs.len;
    } while (!finished);

    {
        UINT branch;
        for (branch = 0; branch < internalCount; ++branch)
        {
            UINT target;
            INT32 delta;
            for (target = 0; target < ct->nIP; ++target)
                if (ct->oldIPs[target] == internalBranches[branch].oldTarget)
                    break;
            /* An entry into the middle of another decoded instruction has
             * no supported mapping, even when its original offset fits. */
            if (target == ct->nIP)
                return FALSE;
            delta = (INT32)ct->newIPs[target] - internalBranches[branch].newEnd;
            if (internalBranches[branch].width == 1)
            {
                INT8 shortDelta;
                if (delta < -128 || delta > 127)
                    return FALSE;
                shortDelta = (INT8)delta;
                memcpy((LPBYTE)ct->pTrampoline + internalBranches[branch].displacement,
                    &shortDelta, sizeof(shortDelta));
            }
            else
                memcpy((LPBYTE)ct->pTrampoline + internalBranches[branch].displacement,
                    &delta, sizeof(delta));
        }
    }

    // Is there enough place for a long jump?
    if (oldPos < sizeof(JMP_REL)
        && !IsCodePadding((LPBYTE)ct->pTarget + oldPos, sizeof(JMP_REL) - oldPos))
    {
        // Is there enough place for a short jump?
        if (oldPos < sizeof(JMP_REL_SHORT)
            && !IsCodePadding((LPBYTE)ct->pTarget + oldPos, sizeof(JMP_REL_SHORT) - oldPos))
        {
            return FALSE;
        }

        // Can we place the long jump above the function?
        if (!MthInternal_IsExecutableAddress((LPBYTE)ct->pTarget - sizeof(JMP_REL)))
            return FALSE;

        if (!IsCodePadding((LPBYTE)ct->pTarget - sizeof(JMP_REL), sizeof(JMP_REL)))
            return FALSE;

        ct->patchAbove = TRUE;
    }

    ct->codeSize = newPos;
#if defined(_M_X64) || defined(__x86_64__)
    // Create a relay function.
    jmp.address = (ULONG_PTR)ct->pDetour;

    ct->pRelay = (LPBYTE)ct->pTrampoline + newPos;
    memcpy(ct->pRelay, &jmp, sizeof(jmp));
#endif

    return TRUE;
}
