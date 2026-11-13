// SPDX-License-Identifier: GPL-3.0-only
// Owned, bounded function forms; no actual Windows API targets are patched.
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "adapter.h"
#include "identity.h"
using Function=int (__cdecl *)(int);
static void require(bool ok,const char *why)
{if(!ok){std::fprintf(stderr,"FAIL: compatibility %s error=%lu\n",why,GetLastError());ExitProcess(1);}}
static int __cdecl detour(int){return 111;}
static void leaf(BYTE *code,unsigned value)
{
#if defined(_M_X64)
 const BYTE prefix[]={0x89,0xc8,0x05};
#else
 const BYTE prefix[]={0x8b,0x44,0x24,4,0x05};
#endif
 std::memcpy(code,prefix,sizeof(prefix));std::memcpy(code+sizeof(prefix),&value,4);code[sizeof(prefix)+4]=0xc3;
}
int main(int argc,char **argv)
{
 require(argc==2,"case argument");const char *kind=argv[1];
 DWORD baseline,after;require(GetProcessHandleCount(GetCurrentProcess(),&baseline)!=0,"handle baseline");
 BYTE *arena=static_cast<BYTE*>(VirtualAlloc(nullptr,4096,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE));require(arena!=nullptr,"source allocation");
 std::memset(arena,0x90,4096);BYTE *code=arena+128,*helper=arena+512;leaf(code,7);leaf(helper,7);
 void *target=code;int expected=10;bool creationOnly=false,registeredSource=false;
#if defined(_M_X64)
 RUNTIME_FUNCTION source{128,256,2048};
#endif
 if(!std::strcmp(kind,"leaf")){}
 else if(!std::strcmp(kind,"rip_load"))
 {
  unsigned value=7;std::memcpy(arena+1024,&value,4);
#if defined(_M_X64)
  const BYTE bytes[]={0x8b,0x05,0,0,0,0,0x03,0xc1,0xc3};std::memcpy(code,bytes,sizeof(bytes));
  INT32 delta=static_cast<INT32>(arena+1024-(code+6));std::memcpy(code+2,&delta,4);
#else
  const BYTE bytes[]={0xa1,0,0,0,0,0x03,0x44,0x24,4,0xc3};std::memcpy(code,bytes,sizeof(bytes));
  DWORD address=reinterpret_cast<DWORD>(arena+1024);std::memcpy(code+1,&address,4);
#endif
 }
 else if(!std::strcmp(kind,"relative_jump"))
 {code[0]=0xe9;INT32 delta=static_cast<INT32>(helper-(code+5));std::memcpy(code+1,&delta,4);}
 else if(!std::strcmp(kind,"conditional_branch"))
 {const BYTE prefix[]={0x31,0xc0,0x74,0x3c,0x90};std::memcpy(code,prefix,sizeof(prefix));leaf(code+5,107);leaf(code+64,7);}
 else if(!std::strcmp(kind,"loop_branch"))
 {const BYTE prefix[]={0x31,0xc9,0xff,0xc1,0xe2,0x3a};std::memcpy(code,prefix,sizeof(prefix));leaf(code+6,7);leaf(code+64,107);
#if defined(_M_X64)
 expected=7;
#endif
 }
 else if(!std::strcmp(kind,"hotpatch_short"))
 {
#if defined(_M_X64)
  code[0]=0x89;code[1]=0xc8;expected=3;
#else
  code[0]=0x31;code[1]=0xc0;expected=0;
#endif
  code[2]=0xc3;code[3]=0x90;code[4]=0xcc;
 }
 else if(!std::strcmp(kind,"relative_call"))
 {
#if defined(_M_X64)
  const BYTE prefix[]={0x48,0x83,0xec,0x28,0xe8,0,0,0,0,0x48,0x83,0xc4,0x28,0xc3};std::memcpy(code,prefix,sizeof(prefix));
  INT32 delta=static_cast<INT32>(helper-(code+9));std::memcpy(code+5,&delta,4);
  const BYTE info[]={1,4,1,0,4,0x42,0,0};std::memcpy(arena+2048,info,sizeof(info));registeredSource=true;
#else
  const BYTE prefix[]={0xff,0x74,0x24,4,0xe8,0,0,0,0,0x83,0xc4,4,0xc3};std::memcpy(code,prefix,sizeof(prefix));
  INT32 delta=static_cast<INT32>(helper-(code+9));std::memcpy(code+5,&delta,4);
#endif
 }
 else if(!std::strcmp(kind,"registered_nonleaf")||!std::strcmp(kind,"interior_entry"))
 {
#if defined(_M_X64)
  const BYTE prefix[]={0x53,0x48,0x83,0xec,0x20};std::memcpy(code,prefix,sizeof(prefix));leaf(code+5,7);code[12]=0x48;code[13]=0x83;code[14]=0xc4;code[15]=0x20;code[16]=0x5b;code[17]=0xc3;
  const BYTE info[]={1,5,2,0,5,0x32,1,0x30};std::memcpy(arena+2048,info,sizeof(info));registeredSource=true;
  if(!std::strcmp(kind,"interior_entry")){target=code+5;creationOnly=true;}
#else
  std::puts("{\"status\":\"NOT_APPLICABLE\",\"reason\":\"x64_runtime_metadata\"}");require(VirtualFree(arena,0,MEM_RELEASE)!=0,"source release");return 0;
#endif
 }
 else if(!std::strcmp(kind,"frame_byte_ch"))
 {
#if defined(_M_X64)
  const BYTE prefix[]={0x55,0x48,0x89,0xe5,0xb5,0x12,0xb8,7,0,0,0,0x5d,0xc3};std::memcpy(code,prefix,sizeof(prefix));expected=7;
  const BYTE info[]={1,4,2,5,4,3,1,0x50};std::memcpy(arena+2048,info,sizeof(info));registeredSource=true;
#else
  std::puts("{\"status\":\"NOT_APPLICABLE\",\"reason\":\"x64_frame_filter\"}");require(VirtualFree(arena,0,MEM_RELEASE)!=0,"source release");return 0;
#endif
 }
 else if(!std::strcmp(kind,"handler_body"))
 {
#if defined(_M_X64)
  const BYTE info[]={9,0,0,0,0,2,0,0};std::memcpy(arena+2048,info,sizeof(info));registeredSource=true;creationOnly=true;
#else
  std::puts("{\"status\":\"NOT_APPLICABLE\",\"reason\":\"x64_handler_metadata\"}");require(VirtualFree(arena,0,MEM_RELEASE)!=0,"source release");return 0;
#endif
 }
 else if(!std::strncmp(kind,"prefixed_",9))
 {
  creationOnly=true;code[0]=0x66;unsigned n=1;
  if(!std::strcmp(kind,"prefixed_call"))code[n++]=0xe8;
  else if(!std::strcmp(kind,"prefixed_jump"))code[n++]=0xe9;
  else {require(!std::strncmp(kind,"prefixed_jcc_",13),"known prefixed case");unsigned condition=std::strtoul(kind+13,nullptr,10);require(condition<16,"Jcc condition");code[n++]=0x0f;code[n++]=static_cast<BYTE>(0x80+condition);}
  code[n++]=5;code[n++]=0;code[n++]=0;code[n++]=0;
 }
 else require(false,"known source form");
#if defined(_M_X64)
 if(registeredSource)require(RtlAddFunctionTable(&source,1,reinterpret_cast<DWORD64>(arena))!=0,"source metadata registration");
#endif
 require(FlushInstructionCache(GetCurrentProcess(),arena,4096)!=0,"source code flush");
 BYTE snapshot[4096];std::memcpy(snapshot,arena,sizeof(snapshot));
 if(!creationOnly)require(reinterpret_cast<Function>(target)(3)==expected,"source oracle");
 require(engine_init(),"engine initialization");void *targets[]={target},*detours[]={reinterpret_cast<void*>(detour)};
 bool accepted=engine_create(targets,detours,1);
 if(accepted)accepted=engine_enable(nullptr,0);
 const char *unwind="NOT_APPLICABLE";
 if(accepted&&!creationOnly)
 {
  require(reinterpret_cast<Function>(target)(3)==111,"detour result");require(originals[0]!=nullptr&&reinterpret_cast<Function>(originals[0])(3)==expected,"exact original result");
#if defined(_M_X64)
  if(registeredSource)
  {
   DWORD64 imageBase=0,frame=0;CONTEXT context{};PVOID handler;
   unsigned offset=!std::strcmp(kind,"relative_call")?20:!std::strcmp(kind,"frame_byte_ch")?6:5;
   auto *entry=RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(originals[0])+offset,&imageBase,nullptr);
   unwind=entry?"REGISTERED_NOT_PROBED":"MISSING_TRAMPOLINE_METADATA";
#if defined(BACKEND_MTH)
   require(entry!=nullptr,"owned generated metadata");DWORD64 stack[16];std::memset(stack,0x55,sizeof(stack));stack[4]=0x22113344;stack[5]=0x12345678;
   context.ContextFlags=CONTEXT_FULL;context.Rip=reinterpret_cast<DWORD64>(originals[0])+offset;
   bool frameCase=!std::strcmp(kind,"frame_byte_ch");context.Rsp=reinterpret_cast<DWORD64>(frameCase?stack+4:stack);context.Rbp=frameCase?reinterpret_cast<DWORD64>(stack+4):0;context.Rbx=0x88776655;
   RtlVirtualUnwind(0,imageBase,context.Rip,entry,&context,&handler,&frame,nullptr);
   require(context.Rip==stack[5]&&context.Rsp==reinterpret_cast<DWORD64>(stack+6),"exact generated caller return/stack");
   if(frameCase)require(context.Rbp==stack[4],"CH alias preserves RBP unwind");
   if(!std::strcmp(kind,"registered_nonleaf"))require(context.Rbx==stack[4],"generated RBX restoration");
   unwind="VERIFIED_EXACT_CALLER";
#endif
  }
#endif
 }
 if(accepted)require(engine_disable(nullptr,0),"disable/detach owner");
 require(engine_retire(),"retire every created owner");
 require(!std::memcmp(snapshot,arena,sizeof(snapshot)),"every source/metadata byte restored");
 if(!creationOnly)require(reinterpret_cast<Function>(target)(3)==expected,"retired source oracle");
#if defined(_M_X64)
 if(registeredSource)require(RtlDeleteFunctionTable(&source)!=0,"source metadata retirement");
#endif
 require(VirtualFree(arena,0,MEM_RELEASE)!=0,"source release");require(GetProcessHandleCount(GetCurrentProcess(),&after)!=0&&after==baseline,"exact handle cleanup");
 std::printf("{\"engine\":\"%s\",\"case\":\"%s\",\"status\":\"%s\",\"unwind\":\"%s\",\"cleanup\":true,\"source_digest\":\"%s\",\"input_digest\":\"%s\"}\n",BENCH_ENGINE,kind,accepted?(creationOnly?"CREATION_ONLY_NOT_SEMANTICALLY_VALIDATED":"CALL_BEHAVIOR_VERIFIED"):"API_REJECTED",unwind,BENCH_SOURCE_DIGEST,BENCH_INPUT_DIGEST);
 return 0;
}
