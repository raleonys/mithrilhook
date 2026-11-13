// SPDX-License-Identifier: GPL-3.0-only
// Create/remove only: never enable a hook or call a target/trampoline.
// Reports compatibility; a supported/refused classification is not application acceptance.
#include <windows.h>
#include <MithrilHook.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void require(BOOL ok,const char *why)
{
    if(!ok){fprintf(stderr,"FAIL: %s\n",why);ExitProcess(1);}
}
static void WINAPI unused_detour(void) {}

int main(void)
{
    static const WCHAR *modules[]={L"ws2_32.dll",L"KernelBase.dll",L"shell32.dll",L"crypt32.dll"};
    static const struct {unsigned module;const char *name;} targets[]={
        {0,"connect"},{1,"RegOpenKeyExA"},{1,"RegOpenKeyExW"},{1,"RegCloseKey"},
        {1,"RegQueryValueExA"},{1,"RegQueryValueExW"},{1,"CreateProcessA"},{1,"CreateProcessW"},
        {2,"SHGetFolderPathA"},{2,"SHGetFolderPathW"},{3,"CryptQueryObject"}
    };
    HMODULE handles[4];unsigned i,accepted=0,refused=0;
    for(i=0;i<4;++i){handles[i]=LoadLibraryW(modules[i]);require(handles[i]!=NULL,"load held target-probe module");}
    require(MTH_Initialize()==MTH_OK,"initialize target compatibility probe");
    for(i=0;i<sizeof(targets)/sizeof(targets[0]);++i)
    {
        FARPROC target=GetProcAddress(handles[targets[i].module],targets[i].name);
        LPVOID original=(LPVOID)(ULONG_PTR)0x1234;
        BYTE before[5],after[5];SIZE_T copied;
        MTH_STATUS status;
        require(target!=NULL,"resolve real application hook target");
        require(ReadProcessMemory(GetCurrentProcess(),(LPCVOID)target,before,sizeof(before),&copied) && copied==sizeof(before),"read immutable pre-probe target bytes");
        status=MTH_CreateHook((LPVOID)target,(LPVOID)unused_detour,&original);
        if(status==MTH_OK)
        {
            ++accepted;require(original!=(LPVOID)(ULONG_PTR)0x1234 && original!=NULL,"supported target publishes an owned original");
            require(MTH_RemoveHook((LPVOID)target)==MTH_OK,"remove disabled target-probe owner");
        }
        else
        {
            ++refused;
            require(status==MTH_ERROR_UNSUPPORTED_FUNCTION && original==(LPVOID)(ULONG_PTR)0x1234,"unsupported target refuses without publishing an original");
        }
        require(ReadProcessMemory(GetCurrentProcess(),(LPCVOID)target,after,sizeof(after),&copied) && copied==sizeof(after) && !memcmp(before,after,sizeof(before)),"create/remove probe never changes target bytes");
        printf("TARGET_PROBE name=%s status=%s enabled=0 executed=0\n",targets[i].name,MTH_StatusToString(status));
    }
    require(MTH_Uninitialize()==MTH_OK,"retire compatibility-probe engine");
    for(i=0;i<4;++i)require(FreeLibrary(handles[i]),"release held target-probe module");
    printf("TARGET_PROBE_SUMMARY accepted=%u refused=%u total=11 application_acceptance=NOT_ESTABLISHED\n",accepted,refused);
    return 0;
}
