// SPDX-License-Identifier: GPL-3.0-only
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <MithrilHook.h>
static unsigned observed;
static LPVOID WINAPI reenter_heap(HANDLE heap,DWORD flags,SIZE_T size) {
    if(MTH_IsOperationInProgressOnThisThread()) {
        LPVOID output=(LPVOID)(ULONG_PTR)0x1234;
        if(MTH_Initialize()!=MTH_ERROR_REENTRANT_CALL ||
           MTH_QueueEnableHook(MTH_ALL_HOOKS)!=MTH_ERROR_REENTRANT_CALL ||
           MTH_CreateHook(NULL,NULL,&output)!=MTH_ERROR_REENTRANT_CALL ||
           output!=(LPVOID)(ULONG_PTR)0x1234) exit(1);
        ++observed;
    }
    return HeapAlloc(heap,flags,size);
}
#define HeapAlloc reenter_heap
#include "hook.c"
int main(void) {
    BYTE *arena,*guarded;void *original=NULL;DWORD oldProtect;
    if(MTH_Initialize()!=MTH_OK) return 1;
    arena=VirtualAlloc(NULL,128,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    if(!arena) return 1;
    memset(arena,0x90,128);arena[16]=arena[64]=0xc3;
    guarded=VirtualAlloc(NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    if(!guarded || !VirtualProtect(guarded,4096,PAGE_EXECUTE_READ|PAGE_GUARD,&oldProtect)) return 1;
    original=(void *)(ULONG_PTR)0x1234;
    if(MTH_CreateHook(arena,guarded,&original)!=MTH_ERROR_NOT_EXECUTABLE || original!=(void *)(ULONG_PTR)0x1234) return 1;
    if(!VirtualProtect(guarded,4096,PAGE_EXECUTE_READWRITE,&oldProtect) || !VirtualFree(guarded,0,MEM_RELEASE)) return 1;
    original=NULL;
    if(MTH_CreateHook(arena,arena+64,&original)!=MTH_OK || !observed || !original) return 1;
    if(MTH_IsOperationInProgressOnThisThread() || MTH_Uninitialize()!=MTH_OK) return 1;
    if(!VirtualFree(arena,0,MEM_RELEASE)) return 1;
    puts("PASS: same-thread recursive operations refused, output preserved, owner released");
    return 0;
}
