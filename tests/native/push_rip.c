// SPDX-License-Identifier: GPL-3.0-only
#include <windows.h>
#include <MithrilHook.h>
#include <stdio.h>
#include <string.h>
typedef DWORD64 (__cdecl *FUNCTION)(void);
static unsigned checks;
static void require(BOOL ok,const char *why)
{++checks;if(!ok){fprintf(stderr,"FAIL: %s\n",why);ExitProcess(1);}}
static void marker(void) {}
static void unwind_at(BYTE *pc,UINT version,DWORD64 pushed)
{
    _Alignas(16) DWORD64 stack[4];
    CONTEXT context;DWORD64 base,frame;PVOID handler;
    PRUNTIME_FUNCTION function=RtlLookupFunctionEntry((DWORD64)(ULONG_PTR)pc,&base,NULL);
    require(function!=NULL,"PUSH source/original has an owned runtime function");
    require((*(const BYTE*)(ULONG_PTR)(base+function->UnwindData)&7)==version,"source v1 and generated v2 metadata remain distinct");
    stack[0]=pushed;stack[1]=(DWORD64)(ULONG_PTR)marker;stack[2]=stack[3]=0;
    memset(&context,0,sizeof(context));context.ContextFlags=CONTEXT_FULL;
    context.Rip=(DWORD64)(ULONG_PTR)pc;context.Rsp=(DWORD64)(ULONG_PTR)stack;
    (void)RtlVirtualUnwind(0,base,context.Rip,function,&context,&handler,&frame,NULL);
    require(context.Rip==stack[1]&&context.Rsp==(DWORD64)(ULONG_PTR)(stack+2),"genuine Windows unwind restores exact PUSH caller and stack");
}
int main(void)
{
    static const struct {BYTE bytes[4];UINT size;} prefixes[]={
        {{0},0},{{0x48},1},{{0x66,0x48},2},{{0x48,0x66,0x48},3},
        {{0x66,0x4f},2},{{0x66,0x48,0x40,0x48},4}
    };
    static const INT addresses[]={-8,-7,-1,0,4,5,64};
    const BYTE tail[]={0x48,0x8b,0x04,0x24,0x48,0x83,0xc4,8,0xc3};
    BYTE *area,*source,*detour;DWORD before,after;UINT prefix,test;
    require(GetProcessHandleCount(GetCurrentProcess(),&before),"capture PUSH handle baseline");
    area=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    require(area!=NULL,"allocate owned PUSH fixture");source=area+256;detour=area+1024;
    memset(area,0x90,4096);detour[0]=0xb8;detour[1]=9;memset(detour+2,0,3);detour[5]=0xc3;
    require(MTH_Initialize()==MTH_OK,"initialize PUSH fixture engine");
    for(prefix=0;prefix<sizeof(prefixes)/sizeof(prefixes[0]);++prefix)
    for(test=0;test<sizeof(addresses)/sizeof(addresses[0]);++test)
    {
        BYTE snapshot[96],info[8]={1,0,1,0,0,2,0,0};UINT size=prefixes[prefix].size,length=size+6,index;
        INT32 displacement=addresses[test]-(INT32)length;
        BOOL overlap=addresses[test]<5&&addresses[test]+8>0;
        DWORD64 expected;LPVOID original=(LPVOID)(ULONG_PTR)0x1234;
        RUNTIME_FUNCTION function={256,0,2048};
        memset(source-16,0x90,128);
        for(index=0;index<16;++index)source[-16+(INT)index]=(BYTE)(index+1);
        for(index=0;index<8;++index)source[64+index]=(BYTE)(index+1);
        memcpy(source,prefixes[prefix].bytes,size);source[size]=0xff;source[size+1]=0x35;
        memcpy(source+size+2,&displacement,4);memcpy(source+length,tail,sizeof(tail));
        info[1]=info[4]=(BYTE)length;memcpy(area+2048,info,sizeof(info));function.EndAddress=256+length+(DWORD)sizeof(tail);
        memcpy(&expected,source+addresses[test],8);memcpy(snapshot,source-16,sizeof(snapshot));
        require(FlushInstructionCache(GetCurrentProcess(),area,4096),"flush balanced PUSH source and detour");
        require(RtlAddFunctionTable(&function,1,(DWORD64)(ULONG_PTR)area),"register ABI-valid eight-byte PUSH source allocation");
        require(((FUNCTION)source)()==expected,"source PUSH independently returns the full expected qword");
        unwind_at(source+length,1,expected);
        if(overlap)
        {
            require(MTH_CreateHook(source,detour,&original)==MTH_ERROR_UNSUPPORTED_FUNCTION,"overlapping qword PUSH refuses before original publication");
            require(original==(LPVOID)(ULONG_PTR)0x1234&&!memcmp(snapshot,source-16,sizeof(snapshot)),"PUSH refusal preserves output, source and adjacent data");
        }
        else
        {
            require(MTH_CreateHook(source,detour,&original)==MTH_OK&&original!=(LPVOID)(ULONG_PTR)0x1234,"publish proven disjoint qword PUSH original");
            require(((FUNCTION)original)()==expected,"disjoint PUSH original retains all eight bytes before enable");
            unwind_at((BYTE*)original+length,2,expected);
            require(MTH_EnableHook(source)==MTH_OK&&((FUNCTION)source)()==9&&((FUNCTION)original)()==expected,"enabled target and original preserve distinct PUSH results");
            unwind_at((BYTE*)original+length,2,expected);
            require(MTH_DisableHook(source)==MTH_OK&&!memcmp(snapshot,source-16,sizeof(snapshot)),"disable restores PUSH code and adjacent data");
            require(MTH_RemoveHook(source)==MTH_OK&&((FUNCTION)source)()==expected,"retire generated PUSH table and code owner");
        }
        require(RtlDeleteFunctionTable(&function),"delete source table after generated owners retire");
    }
    require(MTH_Uninitialize()==MTH_OK,"complete PUSH fixture engine cleanup");
    require(VirtualFree(area,0,MEM_RELEASE),"release PUSH fixture last");
    require(GetProcessHandleCount(GetCurrentProcess(),&after)&&after==before,"restore PUSH handle baseline");
    printf("PASS: %u native PUSH range/execution/unwind/publication/cleanup checks\n",checks);return 0;
}
