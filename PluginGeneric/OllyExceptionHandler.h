#pragma once

#include <ntdll/ntdll.h>

typedef BOOL (WINAPI *t_WaitForDebugEvent)(LPDEBUG_EVENT lpDebugEvent,DWORD dwMilliseconds);

BOOL WINAPI HookedWaitForDebugEvent(LPDEBUG_EVENT lpDebugEvent,DWORD dwMilliseconds);

void HookDebugLoop();
