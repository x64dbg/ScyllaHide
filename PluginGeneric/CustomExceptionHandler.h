#pragma once

#include <ntdll/ntdll.h>

typedef BOOL (WINAPI *t_WaitForDebugEvent)(LPDEBUG_EVENT lpDebugEvent,DWORD dwMilliseconds);
typedef BOOL (WINAPI *t_ContinueDebugEvent)(DWORD dwProcessId,DWORD dwThreadId,DWORD dwContinueStatus);

BOOL WINAPI HookedWaitForDebugEvent(LPDEBUG_EVENT lpDebugEvent,DWORD dwMilliseconds);
BOOL WINAPI HookedContinueDebugEvent(DWORD dwProcessId,DWORD dwThreadId,DWORD dwContinueStatus);

void HookDebugLoop();

