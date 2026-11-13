#include "windows.h"
#include <stdlib.h>
static BYTE *arena;
static SIZE_T arena_size;
static DWORD page_protection[2];
void GetSystemInfo(SYSTEM_INFO *info) { info->dwPageSize=4096; }
void *VirtualAlloc(void *address,SIZE_T size,DWORD flags,DWORD protect) {
    (void)address;(void)flags;if(arena || size>8192)return NULL;
    arena=malloc(size);arena_size=size;page_protection[0]=page_protection[1]=protect;return arena;
}
BOOL VirtualFree(void *address,SIZE_T size,DWORD flags) {
    (void)size;(void)flags;if(address!=arena)return FALSE;
    free(arena);arena=NULL;arena_size=0;return TRUE;
}
BOOL VirtualProtect(void *address,SIZE_T size,DWORD protect,DWORD *old) {
    uintptr_t offset=(uintptr_t)address-(uintptr_t)arena;
    if(!arena || offset>=arena_size || size>arena_size-offset)return FALSE;
    *old=page_protection[offset/4096];
    for(SIZE_T p=offset/4096;p<=(offset+size-1)/4096;++p)page_protection[p]=protect;
    return TRUE;
}
SIZE_T VirtualQuery(const void *address,MEMORY_BASIC_INFORMATION *out,SIZE_T size) {
    uintptr_t offset=(uintptr_t)address-(uintptr_t)arena;
    if(!arena || offset>=arena_size)return 0;
    unsigned page=(unsigned)(offset/4096);
    out->BaseAddress=arena+page*4096;out->AllocationBase=arena;
    out->RegionSize=4096;out->State=MEM_COMMIT;out->Protect=page_protection[page];return size;
}
void *GetCurrentProcess(void) { return (void *)(uintptr_t)1; }
BOOL ReadProcessMemory(void *process,const void *address,void *output,SIZE_T size,SIZE_T *copied) {
    (void)process;MEMORY_BASIC_INFORMATION info;
    if(!VirtualQuery(address,&info,sizeof(info)) || (info.Protect&(PAGE_NOACCESS|PAGE_GUARD))) { *copied=0;return FALSE; }
    uintptr_t offset=(uintptr_t)address-(uintptr_t)arena;
    if(size>4096-offset%4096){*copied=0;return FALSE;}
    memcpy(output,address,size);*copied=size;return TRUE;
}
BOOL MthInternal_IsExecutableAddress(void *address) {
    MEMORY_BASIC_INFORMATION info;
    return VirtualQuery(address,&info,sizeof(info)) && info.State==MEM_COMMIT &&
        (info.Protect&(PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)) &&
        !(info.Protect&(PAGE_GUARD|PAGE_NOACCESS));
}
