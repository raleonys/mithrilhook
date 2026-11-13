// SPDX-License-Identifier: GPL-3.0-only
// Includes/links only the installed package; no source-tree engine target.
#include <windows.h>
#include <MithrilHook.h>
#include <cstdio>
#include <cstring>
static void require(bool ok,const char *why)
{if(!ok){std::fprintf(stderr,"FAIL: installed consumer %s\n",why);ExitProcess(1);}}
int main()
{
 DWORD before,after;require(GetProcessHandleCount(GetCurrentProcess(),&before)!=0,"handle baseline");
 auto *code=static_cast<BYTE*>(VirtualAlloc(nullptr,4096,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE));require(code!=nullptr,"source owner");
 std::memset(code,0x90,4096);const BYTE source[]={0xb8,42,0,0,0,0xc3},detour[]={0xb8,9,0,0,0,0xc3};
 std::memcpy(code,source,sizeof(source));std::memcpy(code+64,detour,sizeof(detour));
 require(FlushInstructionCache(GetCurrentProcess(),code,4096)!=0,"source flush");
 using Function=int (__cdecl *)();void *original=nullptr;
 require(MTH_Initialize()==MTH_OK,"initialize public API");
 require(MTH_CreateHook(code,code+64,&original)==MTH_OK&&original!=nullptr,"publish original");
 require(reinterpret_cast<Function>(code)()==42&&reinterpret_cast<Function>(original)()==42,"source and original result");
 require(MTH_EnableHook(code)==MTH_OK,"enable installed engine");
 require(reinterpret_cast<Function>(code)()==9&&reinterpret_cast<Function>(original)()==42,"detour and original result");
 require(MTH_QueueDisableHook(code)==MTH_OK&&MTH_ApplyQueued()==MTH_OK,"queued disable through installed API");
 require(!std::memcmp(code,source,sizeof(source))&&reinterpret_cast<Function>(code)()==42,"restored source");
 require(MTH_RemoveHook(code)==MTH_OK&&MTH_Uninitialize()==MTH_OK,"retire every engine owner");
 require(VirtualFree(code,0,MEM_RELEASE)!=0,"release source last");
 require(GetProcessHandleCount(GetCurrentProcess(),&after)!=0&&after==before,"handle cleanup");
 std::puts("PASS: installed MithrilHook package consumer, public calls, restored bytes and cleanup");
}
