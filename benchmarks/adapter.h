// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <windows.h>
constexpr unsigned MAX_HOOKS=64;
extern void *originals[MAX_HOOKS];
bool engine_init();
bool engine_create(void **targets,void **detours,unsigned count);
bool engine_enable(HANDLE *peers,unsigned peerCount);
bool engine_disable(HANDLE *peers,unsigned peerCount);
bool engine_retire();
bool engine_single(bool enabled,HANDLE *peers,unsigned peerCount);
bool engine_reapply(bool enabled,HANDLE *peers,unsigned peerCount);
const char *engine_contract();
bool engine_has_separate_create();
