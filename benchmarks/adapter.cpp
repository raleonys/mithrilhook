// SPDX-License-Identifier: GPL-3.0-only
#include "adapter.h"
#if defined(BACKEND_MTH)
#include <MithrilHook.h>
#elif defined(BACKEND_MH) || defined(BACKEND_MHD)
#include <MinHook.h>
#elif defined(BACKEND_DETOURS)
#include <detours.h>
#elif defined(BACKEND_SLIM)
#include <SlimDetours.h>
#endif
void *originals[MAX_HOOKS]; // Persistent-address output slots, including MinHook-Detours.
static void **ownedTargets,**ownedDetours;
static unsigned ownedCount,createdCount;
bool engine_init()
{
 createdCount=0;
#if defined(BACKEND_MTH)
 return MTH_Initialize()==MTH_OK;
#elif defined(BACKEND_MH) || defined(BACKEND_MHD)
 return MH_Initialize()==MH_OK;
#else
 return true;
#endif
}
bool engine_has_separate_create()
{
#if defined(BACKEND_MTH) || defined(BACKEND_MH) || defined(BACKEND_MHD)
 return true;
#else
 return false;
#endif
}
bool engine_create(void **targets,void **detours,unsigned count)
{
 ownedTargets=targets;ownedDetours=detours;ownedCount=count;
 for(unsigned i=0;i<count;++i)
 {
#if defined(BACKEND_MTH)
  if(MTH_CreateHook(targets[i],detours[i],&originals[i])!=MTH_OK)return false;
#elif defined(BACKEND_MH) || defined(BACKEND_MHD)
  if(MH_CreateHook(targets[i],detours[i],&originals[i])!=MH_OK)return false;
#else
  originals[i]=targets[i]; // No equivalent separate create API: bookkeeping only.
#endif
  ++createdCount;
 }
 return true;
}
#if defined(BACKEND_DETOURS) || defined(BACKEND_SLIM)
static bool transaction(bool enable,HANDLE *peers,unsigned peerCount,bool single=false)
{
#if defined(BACKEND_DETOURS)
 if(DetourTransactionBegin()!=NO_ERROR)return false;
 if(DetourUpdateThread(GetCurrentThread())!=NO_ERROR){DetourTransactionAbort();return false;}
 // Explicitly cover every owned idle peer. Detours does not enumerate the
 // process automatically; this is a distinct adapter contract, not a new core guarantee.
 for(unsigned i=0;i<peerCount;++i)
  if(DetourUpdateThread(peers[i])!=NO_ERROR){DetourTransactionAbort();return false;}
 for(unsigned i=0;i<(single?1:ownedCount);++i)
  if((enable?DetourAttach(&originals[i],ownedDetours[i]):DetourDetach(&originals[i],ownedDetours[i]))!=NO_ERROR)
   {DetourTransactionAbort();return false;}
 return DetourTransactionCommit()==NO_ERROR;
#else
 (void)peers;(void)peerCount;
 if(FAILED(SlimDetoursTransactionBegin()))return false; // Default automatic thread suspension remains enabled.
 for(unsigned i=0;i<(single?1:ownedCount);++i)
  if(FAILED(enable?SlimDetoursAttach(&originals[i],ownedDetours[i]):SlimDetoursDetach(&originals[i],ownedDetours[i])))
   {SlimDetoursTransactionAbort();return false;}
 return SUCCEEDED(SlimDetoursTransactionCommit());
#endif
}
#endif
bool engine_enable(HANDLE *peers,unsigned peerCount)
{
#if defined(BACKEND_MTH)
 (void)peers;(void)peerCount;return MTH_EnableHook(MTH_ALL_HOOKS)==MTH_OK;
#elif defined(BACKEND_MH) || defined(BACKEND_MHD)
 (void)peers;(void)peerCount;return MH_EnableHook(MH_ALL_HOOKS)==MH_OK;
#else
 return transaction(true,peers,peerCount);
#endif
}
bool engine_disable(HANDLE *peers,unsigned peerCount)
{
#if defined(BACKEND_MTH)
 (void)peers;(void)peerCount;return MTH_DisableHook(MTH_ALL_HOOKS)==MTH_OK;
#elif defined(BACKEND_MH) || defined(BACKEND_MHD)
 (void)peers;(void)peerCount;return MH_DisableHook(MH_ALL_HOOKS)==MH_OK;
#else
 return transaction(false,peers,peerCount);
#endif
}
bool engine_retire()
{
#if defined(BACKEND_MTH)
 for(unsigned i=0;i<createdCount;++i)if(MTH_RemoveHook(ownedTargets[i])!=MTH_OK)return false;
 return MTH_Uninitialize()==MTH_OK;
#elif defined(BACKEND_MH) || defined(BACKEND_MHD)
 for(unsigned i=0;i<createdCount;++i)if(MH_RemoveHook(ownedTargets[i])!=MH_OK)return false;
 return MH_Uninitialize()==MH_OK;
#else
 return true; // Detach commit already performs backend retirement.
#endif
}
const char *engine_contract()
{
#if defined(BACKEND_MTH)
 return "strict automatic coverage and physical-state repair; registry/retirement scan and retry ownership";
#elif defined(BACKEND_MHD)
 return "distinct MinHook-Detours API; default automatic suspension; persistent original slots";
#elif defined(BACKEND_DETOURS)
 return "transaction attach/detach; explicit UpdateThread for current and all owned idle peers";
#elif defined(BACKEND_SLIM)
 return "official SlimDetours transaction; default automatic suspension; pinned PHNT headers";
#elif defined(MH_SAFE_FREEZE)
 return "patched SAFE-FREEZE ON; completion and retirement ownership; Citrine relocation";
#else
 return "MinHook-family default original freeze; no unsafe-none mode";
#endif
}

bool engine_single(bool enabled,HANDLE *peers,unsigned peerCount)
{
#if defined(BACKEND_MTH)
 (void)peers;(void)peerCount;
 return (enabled?MTH_EnableHook(ownedTargets[0]):MTH_DisableHook(ownedTargets[0]))==MTH_OK;
#elif defined(BACKEND_MH) || defined(BACKEND_MHD)
 (void)peers;(void)peerCount;
 return (enabled?MH_EnableHook(ownedTargets[0]):MH_DisableHook(ownedTargets[0]))==MH_OK;
#else
 return transaction(enabled,peers,peerCount,true);
#endif
}
bool engine_reapply(bool enabled,HANDLE *peers,unsigned peerCount)
{
#if defined(BACKEND_MTH)
 (void)peers;(void)peerCount;
 if((enabled?MTH_QueueEnableHook(MTH_ALL_HOOKS):MTH_QueueDisableHook(MTH_ALL_HOOKS))!=MTH_OK)return false;
 return MTH_ApplyQueued()==MTH_OK;
#elif defined(BACKEND_MH) || defined(BACKEND_MHD)
 (void)peers;(void)peerCount;
 if((enabled?MH_QueueEnableHook(MH_ALL_HOOKS):MH_QueueDisableHook(MH_ALL_HOOKS))!=MH_OK)return false;
 return MH_ApplyQueued()==MH_OK;
#else
 return transaction(enabled,peers,peerCount);
#endif
}
