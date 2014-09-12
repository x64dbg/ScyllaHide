#pragma once

#include <windows.h>

#define STATUS_INVALID_LOCK_SEQUENCE     ((NTSTATUS) 0xC000001E)

typedef BOOL (WINAPI *t_WaitForDebugEvent)(LPDEBUG_EVENT lpDebugEvent,DWORD dwMilliseconds);

BOOL WINAPI HookedWaitForDebugEvent(LPDEBUG_EVENT lpDebugEvent,DWORD dwMilliseconds);

void HookDebugLoop();

