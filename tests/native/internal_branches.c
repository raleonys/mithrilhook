// SPDX-License-Identifier: GPL-3.0-only
#include <windows.h>
#include <MithrilHook.h>
#include <stdio.h>
#include <string.h>

static unsigned checks;
static void require(BOOL ok, const char *why)
{
    ++checks;
    if (!ok) { fprintf(stderr, "FAIL: %s\n", why); ExitProcess(1); }
}

static int execute(BYTE *area, LPVOID entry, int count)
{
    typedef int (__cdecl *WRAPPER)(int);
#if defined(_M_X64) || defined(__x86_64__)
    const BYTE prefix[] = {0x48,0x83,0xec,0x28,0x85,0xc9,0x49,0xbb};
    const BYTE suffix[] = {0x41,0xff,0xd3,0x48,0x83,0xc4,0x28,0xc3};
#else
    const BYTE prefix[] = {0x8b,0x4c,0x24,0x04,0x85,0xc9,0xb8};
    const BYTE suffix[] = {0xff,0xd0,0xc3};
#endif
    ULONG_PTR address = (ULONG_PTR)entry;
    memcpy(area + 1024, prefix, sizeof(prefix));
    memcpy(area + 1024 + sizeof(prefix), &address, sizeof(address));
    memcpy(area + 1024 + sizeof(prefix) + sizeof(address), suffix, sizeof(suffix));
    require(FlushInstructionCache(GetCurrentProcess(), area + 1024, 64), "flush owned balanced-call wrapper");
    return ((WRAPPER)(area + 1024))(count);
}

int main(void)
{
    static const struct
    {
        const char *name;
        BYTE bytes[16];
        UINT length;
        UINT resultOffset;
        UINT inputs; /* 0: -2/-1/0; 1: -2/-1; 2: 0/1/2. */
    } cases[] = {
        {"review-13 short backward JNE", {0x74,6,0xff,0xc1,0x75,0xfa,0x90,0x90,0xb8,42,0,0,0,0xc3},14,8,0},
        {"short backward JMP", {0x74,14,0xff,0xc1,0xeb,0xfa},6,16,0},
        {"near backward JNE", {0x74,14,0xff,0xc1,0x0f,0x85,0xf6,0xff,0xff,0xff},10,16,0},
        {"near backward JMP", {0x74,14,0xff,0xc1,0xe9,0xf7,0xff,0xff,0xff},9,16,0},
        {"plain backward loop", {0x90,0x90,0xff,0xc1,0x75,0xfa},6,16,1},
        {"plain forward JMP", {0xeb,2,0x90,0x90,0x90},5,16,0},
        {"forward JMP after expansion", {0x74,14,0xeb,0,0x90},5,16,0},
        {"forward Jcc after expansion", {0x70,14,0x74,0,0x90},5,16,0},
        {"LOOP after two expansions", {0x74,30,0x70,44,0xe2,0xfa},6,32,2}
    };
    static const BYTE internalOpcodes[] = {0xeb,0x75,0xe0,0xe1,0xe2,0xe3};
    BYTE *area;
    DWORD before, after;
    UINT scenario, input, kind, invalid;
#if defined(_M_X64) || defined(__x86_64__)
    RUNTIME_FUNCTION wrapper = {1024,1048,2048};
    const BYTE unwind[] = {1,4,1,0,4,0x42,0,0};
#endif
    require(GetProcessHandleCount(GetCurrentProcess(), &before), "capture internal-branch handle baseline");
    area = VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    require(area != NULL, "allocate owned internal-branch fixture");
    memset(area,0x90,4096);
#if defined(_M_X64) || defined(__x86_64__)
    memcpy(area + 2048, unwind, sizeof(unwind));
    require(RtlAddFunctionTable(&wrapper,1,(DWORD64)(ULONG_PTR)area), "register ABI-valid wrapper unwind metadata");
#endif
    require(MTH_Initialize() == MTH_OK, "initialize internal-branch engine");
    for (scenario = 0; scenario < sizeof(cases)/sizeof(cases[0]); ++scenario)
    {
        BYTE snapshot[64];
        LPVOID original = NULL;
        UINT inputs = cases[scenario].inputs == 1 ? 2 : 3;
        memset(area,0x90,512);
        memcpy(area,cases[scenario].bytes,cases[scenario].length);
        area[cases[scenario].resultOffset] = 0xb8;
        area[cases[scenario].resultOffset + 1] = 42;
        memset(area + cases[scenario].resultOffset + 2,0,3);
        area[cases[scenario].resultOffset + 5] = 0xc3;
        area[64] = 0xb8; area[65] = 9; memset(area + 66,0,3); area[69] = 0xc3;
        memcpy(snapshot,area,sizeof(snapshot));
        require(FlushInstructionCache(GetCurrentProcess(),area,512), "flush internal-branch source/detour");
        printf("INTERNAL_BRANCH case=%s\n", cases[scenario].name); fflush(stdout);
        for (input = 0; input < inputs; ++input)
        {
            int count = cases[scenario].inputs == 2 ? (int)input : (int)input - 2;
            require(execute(area,area,count) == 42, "source branch path returns independent expected result");
        }
        require(MTH_CreateHook(area,area + 64,&original) == MTH_OK && original != NULL,
            "publish internal-branch original only after valid relocation");
        require(!memcmp(snapshot,area,sizeof(snapshot)), "creation preserves all source bytes");
        for (input = 0; input < inputs; ++input)
        {
            int count = cases[scenario].inputs == 2 ? (int)input : (int)input - 2;
            require(execute(area,original,count) == 42, "trampoline preserves taken/not-taken internal branch result");
        }
        require(MTH_EnableHook(area) == MTH_OK, "enable owned internal-branch target");
        for (input = 0; input < inputs; ++input)
        {
            int count = cases[scenario].inputs == 2 ? (int)input : (int)input - 2;
            require(execute(area,area,count) == 9 && execute(area,original,count) == 42,
                "enabled target detours while original retains internal branch behavior");
        }
        require(MTH_DisableHook(area) == MTH_OK && !memcmp(snapshot,area,sizeof(snapshot)),
            "disable restores every source byte");
        require(MTH_RemoveHook(area) == MTH_OK, "retire internal-branch owner");
        require(execute(area,area,cases[scenario].inputs == 2 ? 2 : -2) == 42,
            "retired source remains callable");
    }
    for (kind = 0; kind < sizeof(internalOpcodes); ++kind)
    for (invalid = 0; invalid < 2; ++invalid)
    {
        BYTE snapshot[64];
        LPVOID original = (LPVOID)(ULONG_PTR)0x1234;
        memset(area,0x90,64); area[0] = 0x74; area[1] = 14;
        area[2] = 0xff; area[3] = 0xc1; area[4] = internalOpcodes[kind]; area[5] = invalid ? 0xfd : 0xfb;
        memcpy(snapshot,area,sizeof(snapshot));
        require(MTH_CreateHook(area,area + 64,&original) == MTH_ERROR_UNSUPPORTED_FUNCTION,
            "refuse internal JMP/Jcc/LOOP destination without an instruction-boundary mapping");
        require(original == (LPVOID)(ULONG_PTR)0x1234 && !memcmp(snapshot,area,sizeof(snapshot)),
            "invalid-target refusal preserves original output and target bytes");
    }
    {
        BYTE snapshot[64];
        LPVOID original = (LPVOID)(ULONG_PTR)0x1234;
        memset(area,0x90,64); area[0] = 0xeb; area[1] = 2; area[2] = 0x74; area[3] = 12;
        memcpy(snapshot,area,sizeof(snapshot));
        require(MTH_CreateHook(area,area + 64,&original) == MTH_ERROR_UNSUPPORTED_FUNCTION,
            "retain conservative forward-span growth refusal");
        require(original == (LPVOID)(ULONG_PTR)0x1234 && !memcmp(snapshot,area,sizeof(snapshot)),
            "forward-span refusal preserves original output and target bytes");
    }
    require(MTH_Uninitialize() == MTH_OK, "complete internal-branch engine cleanup");
#if defined(_M_X64) || defined(__x86_64__)
    require(RtlDeleteFunctionTable(&wrapper), "retire wrapper runtime metadata before storage");
#endif
    require(VirtualFree(area,0,MEM_RELEASE), "release internal-branch fixture storage last");
    require(GetProcessHandleCount(GetCurrentProcess(), &after) && after == before,
        "restore internal-branch handle baseline");
    printf("PASS: %u native internal-branch execution/publication/retirement checks\n", checks);
    return 0;
}
