// SPDX-License-Identifier: GPL-3.0-only
#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <climits>
#include "adapter.h"
#include "identity.h"
using Function=int (__cdecl *)(int);
static volatile LONG callMode;
static Function volatile measuredFunction;
static bool corruptChecksum;
static void require(bool ok,const char *why)
{if(!ok){std::fprintf(stderr,"FAIL: %s error=%lu\n",why,GetLastError());ExitProcess(1);}}
static long long tick(){LARGE_INTEGER value;require(QueryPerformanceCounter(&value)!=0,"QPC");return value.QuadPart;}
static unsigned long long cpu()
{
 FILETIME a,b,k,u;require(GetProcessTimes(GetCurrentProcess(),&a,&b,&k,&u)!=0,"process CPU times");
 ULARGE_INTEGER ki,ui;ki.LowPart=k.dwLowDateTime;ki.HighPart=k.dwHighDateTime;ui.LowPart=u.dwLowDateTime;ui.HighPart=u.dwHighDateTime;
 return ki.QuadPart+ui.QuadPart;
}
static unsigned long long private_bytes()
{PROCESS_MEMORY_COUNTERS_EX info{};info.cb=sizeof(info);require(GetProcessMemoryInfo(GetCurrentProcess(),reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&info),sizeof(info))!=0,"private commit");return info.PrivateUsage;}
static unsigned long long executable_bytes()
{
 unsigned long long total=0;ULONG_PTR address=0;MEMORY_BASIC_INFORMATION info;
 while(VirtualQuery(reinterpret_cast<void*>(address),&info,sizeof(info))==sizeof(info))
 {
  DWORD protection=info.Protect&255;
  if(info.State==MEM_COMMIT&&info.Type==MEM_PRIVATE&&(protection==PAGE_EXECUTE||protection==PAGE_EXECUTE_READ||protection==PAGE_EXECUTE_READWRITE||protection==PAGE_EXECUTE_WRITECOPY))total+=info.RegionSize;
  ULONG_PTR next=reinterpret_cast<ULONG_PTR>(info.BaseAddress)+info.RegionSize;if(next<=address)break;address=next;
 }
 return total;
}
static __declspec(noinline) int __cdecl detour_zero(int x)
{return callMode?reinterpret_cast<Function>(originals[0])(x)+2:x+9;}
struct PeerContext{HANDLE stop,ready;};
static DWORD WINAPI idle_peer(void *argument)
{
 auto *state=static_cast<PeerContext*>(argument);SetEvent(state->ready);
 return WaitForSingleObject(state->stop,INFINITE)==WAIT_OBJECT_0?0:1;
}
static void sample(const char *metric,unsigned index,long long ticks,unsigned operations,unsigned long long checksum=0)
{
 require(ticks>=0&&operations>0,"valid raw timing");
 std::printf("{\"type\":\"sample\",\"metric\":\"%s\",\"sample\":%u,\"ticks\":%lld,\"operations\":%u,\"checksum\":%llu}\n",metric,index,ticks,operations,checksum);
}
static void calls(const char *metric,Function function,unsigned increment)
{
 measuredFunction=function;
 for(unsigned i=0;i<10000;++i)require(measuredFunction(i&1023)==int((i&1023)+increment),"call warmup result");
 constexpr unsigned count=500000;
 constexpr unsigned groups=count/1024,remainder=count%1024;
 unsigned long long expected=static_cast<unsigned long long>(groups)*1023*1024/2+static_cast<unsigned long long>(remainder)*(remainder-1)/2+static_cast<unsigned long long>(count)*increment;
 for(unsigned s=0;s<7;++s)
 {
  unsigned long long sum=0;long long start=tick();
  for(unsigned i=0;i<count;++i)sum+=measuredFunction(i&1023);
  long long elapsed=tick()-start;
  if(corruptChecksum&&!std::strcmp(metric,"detour_original"))++sum;
  require(sum==expected,"complete timed-call checksum");sample(metric,s,elapsed,count,sum);
 }
 measuredFunction=nullptr;
}
struct CallWorker
{
    HANDLE start,ready;Function function;unsigned long long sum;
};
static DWORD WINAPI call_worker(void *argument)
{
    auto *worker=static_cast<CallWorker*>(argument);
    for(unsigned i=0;i<1000;++i)if(worker->function(i&1023)!=int((i&1023)+9))return 1;
    SetEvent(worker->ready);
    if(WaitForSingleObject(worker->start,INFINITE)!=WAIT_OBJECT_0)return 2;
    unsigned long long sum=0;
    for(unsigned i=0;i<500000;++i)sum+=worker->function(i&1023);
    worker->sum=sum;return 0;
}
static void concurrent_calls(Function function,unsigned callers)
{
    constexpr unsigned n=500000,g=n/1024,r=n%1024;
    const unsigned long long expected=(static_cast<unsigned long long>(g)*1023*1024/2+static_cast<unsigned long long>(r)*(r-1)/2+static_cast<unsigned long long>(n)*9)*callers;
    for(unsigned sampleIndex=0;sampleIndex<3;++sampleIndex)
    {
        CallWorker workers[64]{};HANDLE handles[64]{},readyEvents[64]{};
        HANDLE start=CreateEventW(nullptr,TRUE,FALSE,nullptr);require(start!=nullptr,"concurrent start gate");
        for(unsigned i=0;i<callers;++i)
        {
            readyEvents[i]=CreateEventW(nullptr,TRUE,FALSE,nullptr);require(readyEvents[i]!=nullptr,"concurrent ready gate");
            workers[i]={start,readyEvents[i],function,0};handles[i]=CreateThread(nullptr,0,call_worker,&workers[i],0,nullptr);require(handles[i]!=nullptr,"create steady call worker");
        }
        require(WaitForMultipleObjects(callers,readyEvents,TRUE,10000)==WAIT_OBJECT_0,"all steady workers warmed and ready");
        long long begin=tick();require(SetEvent(start)!=0,"release steady workers");
        require(WaitForMultipleObjects(callers,handles,TRUE,60000)==WAIT_OBJECT_0,"steady workers completed");long long elapsed=tick()-begin;
        unsigned long long total=0;
        for(unsigned i=0;i<callers;++i)
        {
            DWORD code;require(GetExitCodeThread(handles[i],&code)!=0&&code==0,"steady worker result");total+=workers[i].sum;
            require(CloseHandle(handles[i])&&CloseHandle(readyEvents[i]),"retire steady worker handles");
        }
        require(total==expected,"complete concurrent-call checksum");require(CloseHandle(start)!=0,"retire steady start gate");
        sample("concurrent_detour_original",sampleIndex,elapsed,n*callers,total);
    }
}

int main(int argc,char **argv)
{
 require(argc==3||argc==4,"usage: driver hooks peers [callers|corrupt-checksum]");
 unsigned count=std::strtoul(argv[1],nullptr,10),peerCount=std::strtoul(argv[2],nullptr,10);
 require(count>0&&count<=MAX_HOOKS&&peerCount<=64,"bounded benchmark recipe");
 corruptChecksum=argc==4&&!std::strcmp(argv[3],"corrupt-checksum");
 unsigned callers=argc==4&&!corruptChecksum?std::strtoul(argv[3],nullptr,10):0;require(callers<=64,"bounded steady caller count");
 DWORD baseline,finalHandles;require(GetProcessHandleCount(GetCurrentProcess(),&baseline)!=0,"initial handle baseline");
 DWORD_PTR processMask,systemMask;require(GetProcessAffinityMask(GetCurrentProcess(),&processMask,&systemMask)!=0&&processMask!=0,"process affinity");
 DWORD_PTR selected=processMask&(~processMask+1);require(SetThreadAffinityMask(GetCurrentThread(),selected)!=0,"pin measurement thread to first allowed CPU");
 SYSTEM_INFO system;GetSystemInfo(&system);LARGE_INTEGER frequency;require(QueryPerformanceFrequency(&frequency)!=0,"QPC frequency");
 long long timerOverhead=LLONG_MAX;for(unsigned i=0;i<10000;++i){long long a=tick(),b=tick();if(b-a<timerOverhead)timerOverhead=b-a;}
 std::printf("{\"type\":\"environment\",\"engine\":\"%s\",\"source_digest\":\"%s\",\"input_digest\":\"%s\",\"compiler\":\"%s\",\"bits\":%u,\"hooks\":%u,\"peers\":%u,\"callers\":%u,\"qpc_frequency\":%lld,\"timer_overhead_ticks\":%lld,\"logical_processors\":%lu,\"affinity\":%llu,\"contract\":\"%s\"}\n",BENCH_ENGINE,BENCH_SOURCE_DIGEST,BENCH_INPUT_DIGEST,BENCH_COMPILER,unsigned(sizeof(void*)*8),count,peerCount,callers,frequency.QuadPart,timerOverhead,system.dwNumberOfProcessors,static_cast<unsigned long long>(selected),engine_contract());
 HANDLE peers[64]{},ready[64]{};PeerContext contexts[64]{};
 HANDLE stop=CreateEventW(nullptr,TRUE,FALSE,nullptr);require(stop!=nullptr,"peer stop event");
 for(unsigned i=0;i<peerCount;++i){ready[i]=CreateEventW(nullptr,TRUE,FALSE,nullptr);require(ready[i]!=nullptr,"peer ready event");contexts[i]={stop,ready[i]};peers[i]=CreateThread(nullptr,0,idle_peer,&contexts[i],0,nullptr);require(peers[i]!=nullptr,"create idle peer");require(WaitForSingleObject(ready[i],5000)==WAIT_OBJECT_0,"peer readiness");}
 auto *arena=static_cast<BYTE*>(VirtualAlloc(nullptr,8192,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE));require(arena!=nullptr,"owned leaf fixture");
 std::memset(arena,0x90,8192);void *targets[MAX_HOOKS]{},*detours[MAX_HOOKS]{};BYTE saved[MAX_HOOKS][16]{};
 for(unsigned i=0;i<count;++i)
 {
  BYTE *code=arena+i*64,*detour=arena+4096+i*64;
#if defined(_M_X64)
  const BYTE prefix[]={0x89,0xc8,0x05};
#else
  const BYTE prefix[]={0x8b,0x44,0x24,4,0x05};
#endif
  std::memcpy(code,prefix,sizeof(prefix));std::memcpy(detour,prefix,sizeof(prefix));
  unsigned value=i+7;std::memcpy(code+sizeof(prefix),&value,4);value=i+9;std::memcpy(detour+sizeof(prefix),&value,4);
  code[sizeof(prefix)+4]=detour[sizeof(prefix)+4]=0xc3;
  targets[i]=code;detours[i]=i?static_cast<void*>(detour):reinterpret_cast<void*>(detour_zero);std::memcpy(saved[i],code,16);
 }
 require(FlushInstructionCache(GetCurrentProcess(),arena,8192)!=0,"flush fixture code");
 calls("direct_call",reinterpret_cast<Function>(targets[0]),7);
 DWORD ownedHandles;require(GetProcessHandleCount(GetCurrentProcess(),&ownedHandles)!=0,"owned peer handle baseline");
 for(unsigned cycle=0;cycle<3;++cycle)
 {
  auto privateBefore=private_bytes(),execBefore=executable_bytes(),cpuBefore=cpu();
  long long install=tick();require(engine_init(),"engine initialization");long long initialized=tick();
  long long createStart=tick();require(engine_create(targets,detours,count),"create/prepare hooks");long long created=tick();
  long long enableStart=tick();require(engine_enable(peers,peerCount),"enable/attach batch");long long installed=tick();
  auto cpuInstall=cpu()-cpuBefore,execInstalled=executable_bytes(),privateInstalled=private_bytes();
  if(engine_has_separate_create())sample("initialize",cycle,initialized-install,1);
  if(engine_has_separate_create())sample("create",cycle,created-createStart,count);
  sample("activate_batch",cycle,installed-enableStart,count);sample("complete_install",cycle,installed-install,count);
  callMode=0;
  for(unsigned i=0;i<count;++i){require(reinterpret_cast<Function>(targets[i])(3)==int(i+12),"every enabled target has its distinct detour result");require(std::memcmp(targets[i],saved[i],16)!=0,"every enabled target was patched");require(originals[i]!=nullptr,"published original slot");require(reinterpret_cast<Function>(originals[i])(3)==int(i+10),"every enabled original restores distinct source behavior");}
  if(cycle==0){calls("detour_only",reinterpret_cast<Function>(targets[0]),9);callMode=1;calls("detour_original",reinterpret_cast<Function>(targets[0]),9);calls("original_trampoline",reinterpret_cast<Function>(originals[0]),7);if(callers)concurrent_calls(reinterpret_cast<Function>(targets[0]),callers);callMode=0;}
  long long toggle=tick();require(engine_single(false,peers,peerCount),"single disable/detach");long long toggled=tick();sample("single_disable",cycle,toggled-toggle,1);
  require(reinterpret_cast<Function>(targets[0])(3)==10,"single-disabled source behavior");
  toggle=tick();require(engine_single(true,peers,peerCount),"single enable/attach");toggled=tick();sample("single_enable",cycle,toggled-toggle,1);
  require(reinterpret_cast<Function>(targets[0])(3)==12,"single re-enabled detour behavior");
  toggle=tick();require(engine_reapply(false,peers,peerCount),"queued/transactional disable");toggled=tick();sample("queued_or_transaction_disable",cycle,toggled-toggle,count);
  for(unsigned i=0;i<count;++i)require(reinterpret_cast<Function>(targets[i])(3)==int(i+10),"batch-disabled source behavior");
  toggle=tick();require(engine_reapply(true,peers,peerCount),"queued/transactional enable");toggled=tick();sample("queued_or_transaction_enable",cycle,toggled-toggle,count);
  for(unsigned i=0;i<count;++i)require(reinterpret_cast<Function>(targets[i])(3)==int(i+12)&&reinterpret_cast<Function>(originals[i])(3)==int(i+10),"batch reactivation restores distinct detour and original behavior");
  cpuBefore=cpu();long long removal=tick();require(engine_disable(peers,peerCount),"disable/detach batch");long long disabled=tick();
  long long retireStart=tick();require(engine_retire(),"retire every hook and engine owner");long long retired=tick();
  auto cpuRemove=cpu()-cpuBefore,execAfter=executable_bytes(),privateAfter=private_bytes();
  sample("disable_batch",cycle,disabled-removal,count);
  if(engine_has_separate_create())sample("retire",cycle,retired-retireStart,count);
  sample("complete_remove",cycle,retired-removal,count);
  for(unsigned i=0;i<count;++i){require(std::memcmp(targets[i],saved[i],16)==0,"retirement restores all source bytes");require(reinterpret_cast<Function>(targets[i])(3)==int(i+10),"retired source executes correctly");originals[i]=nullptr;}
  DWORD handles;require(GetProcessHandleCount(GetCurrentProcess(),&handles)!=0&&handles==ownedHandles,"engine restores exact handle baseline");
  std::printf("{\"type\":\"resources\",\"cycle\":%u,\"private_before\":%llu,\"private_installed\":%llu,\"private_after\":%llu,\"exec_before\":%llu,\"exec_installed\":%llu,\"exec_after\":%llu,\"cpu_install_100ns\":%llu,\"cpu_remove_100ns\":%llu}\n",cycle,privateBefore,privateInstalled,privateAfter,execBefore,execInstalled,execAfter,cpuInstall,cpuRemove);
 }
 require(SetEvent(stop)!=0,"stop idle peers");
 for(unsigned i=0;i<peerCount;++i){require(WaitForSingleObject(peers[i],5000)==WAIT_OBJECT_0,"join idle peer");DWORD code;require(GetExitCodeThread(peers[i],&code)!=0&&code==0,"idle peer completed successfully");require(CloseHandle(peers[i])&&CloseHandle(ready[i]),"retire peer handles");}
 require(CloseHandle(stop)!=0&&VirtualFree(arena,0,MEM_RELEASE)!=0,"retire fixture owners");
 require(GetProcessHandleCount(GetCurrentProcess(),&finalHandles)!=0&&finalHandles==baseline,"restore process handle baseline");
 std::printf("{\"type\":\"complete\",\"cycles\":3,\"hooks\":%u,\"peers\":%u,\"callers\":%u,\"handle_baseline\":%lu,\"handle_final\":%lu,\"errors\":0}\n",count,peerCount,callers,baseline,finalHandles);
 return 0;
}
