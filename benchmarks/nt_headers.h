// SPDX-License-Identifier: GPL-3.0-only
// Official SlimDetours supports a caller-supplied NDK; use the pinned PHNT
// headers bundled with the separately identified MinHook-Detours input.
#include <phnt_windows.h>
#include <phnt.h>
#if defined(_M_X64) && !defined(_M_ARM64EC)
NTSYSAPI BOOLEAN NTAPI RtlIsEcCode(ULONG64 CodePointer);
// These pinned x64 sources use typeof only for &RtlIsEcCode. MSVC v143
// does not implement C23 typeof; spell the identical pointer type in this
// benchmark-only compile context. ARM64/ARM64EC are not benchmark targets.
#if defined(_MSC_VER) && !defined(__clang__) && !defined(__cplusplus)
typedef BOOLEAN (NTAPI *BENCH_RTL_IS_EC_CODE)(ULONG64);
#define typeof(expression) BENCH_RTL_IS_EC_CODE
#endif
#endif
