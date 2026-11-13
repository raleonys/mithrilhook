#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
typedef int BOOL;
typedef void VOID;
typedef void *LPVOID;
typedef const void *LPCVOID;
typedef uint8_t BYTE, UINT8, *LPBYTE;
typedef int8_t INT8;
typedef int16_t INT16;
typedef uint16_t UINT16;
typedef int32_t INT32;
typedef int64_t INT64;
typedef uint32_t DWORD, UINT32, *PUINT32;
typedef uint64_t UINT64;
typedef unsigned int UINT;
typedef uintptr_t ULONG_PTR;
typedef size_t SIZE_T;
#define TRUE 1
#define FALSE 0
#define WINAPI
#define MEM_COMMIT 0x1000u
#define MEM_RESERVE 0x2000u
#define MEM_RELEASE 0x8000u
#define PAGE_NOACCESS 1u
#define PAGE_READONLY 2u
#define PAGE_READWRITE 4u
#define PAGE_WRITECOPY 8u
#define PAGE_EXECUTE 0x10u
#define PAGE_EXECUTE_READ 0x20u
#define PAGE_EXECUTE_READWRITE 0x40u
#define PAGE_EXECUTE_WRITECOPY 0x80u
#define PAGE_GUARD 0x100u
#define ARRAYSIZE(a) (sizeof(a)/sizeof((a)[0]))
typedef struct { DWORD dwPageSize; } SYSTEM_INFO;
typedef struct { void *BaseAddress,*AllocationBase; SIZE_T RegionSize; DWORD State,Protect; } MEMORY_BASIC_INFORMATION;
void GetSystemInfo(SYSTEM_INFO *);
void *VirtualAlloc(void *, SIZE_T, DWORD, DWORD);
BOOL VirtualFree(void *, SIZE_T, DWORD);
BOOL VirtualProtect(void *, SIZE_T, DWORD, DWORD *);
SIZE_T VirtualQuery(const void *, MEMORY_BASIC_INFORMATION *, SIZE_T);
void *GetCurrentProcess(void);
BOOL ReadProcessMemory(void *, const void *, void *, SIZE_T, SIZE_T *);
