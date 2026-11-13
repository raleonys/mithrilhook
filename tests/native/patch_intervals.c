// SPDX-License-Identifier: GPL-3.0-only
/* Exact production interval helper, with synthetic entries but no OS hooks. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "hook.c"
static unsigned checks;
static void require(BOOL ok,const char *why)
{++checks;if(!ok){fprintf(stderr,"FAIL: %s\n",why);ExitProcess(1);}}
int main(void)
{
    static const INT firstOverlap[2][2]={{-4,-1},{-9,-6}};
    static const INT lastOverlap[2][2]={{4,9},{1,6}};
    HOOK_ENTRY entry;
    TRAMPOLINE candidate;
    UINT ownedAbove,newAbove;
    INT offset;
    memset(&entry,0,sizeof(entry));memset(&candidate,0,sizeof(candidate));
    entry.pTarget=(LPVOID)(ULONG_PTR)0x1000;g_hooks.pItems=&entry;g_hooks.size=1;
    for(ownedAbove=0;ownedAbove<2;++ownedAbove)
    for(newAbove=0;newAbove<2;++newAbove)
    for(offset=-16;offset<=16;++offset)
    {
        BOOL overlap=offset>=firstOverlap[ownedAbove][newAbove]&&offset<=lastOverlap[ownedAbove][newAbove];
        entry.patchAbove=(UINT8)ownedAbove;candidate.patchAbove=(BOOL)newAbove;
        candidate.pTarget=(LPVOID)(ULONG_PTR)(0x1000+offset);
        require(IsHookPatchAvailable(&candidate)==!overlap,"normal/hotpatch interval algebra, overlap and exact adjacency");
    }
    g_hooks.size=0;
    require(!IsPatchIntervalAvailable(~(ULONG_PTR)0-1,5),"refuse a wrapping candidate interval");
    require(!IsPatchIntervalAvailable(0x1000,0),"refuse an empty physical write interval");
    candidate.pTarget=(LPVOID)(ULONG_PTR)2;candidate.patchAbove=TRUE;
    require(!IsHookPatchAvailable(&candidate),"refuse hotpatch address underflow");
    g_hooks.size=1;entry.pTarget=(LPVOID)(ULONG_PTR)2;entry.patchAbove=TRUE;
    require(!IsPatchIntervalAvailable(0x1000,5),"an invalid retained interval cannot silently free the reservation");
    g_hooks.pItems=NULL;g_hooks.size=0;
    printf("PASS: %u production patch-interval boundary checks\n",checks);return 0;
}
