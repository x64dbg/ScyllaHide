#pragma once

#include <windows.h>

#define STATUS_INVALID_LOCK_SEQUENCE  ((NTSTATUS) 0xC000001E)
#define STATUS_ASSERTION_FAILURE      ((NTSTATUS) 0xC0000420)
#define STATUS_WX86_BREAKPOINT        ((NTSTATUS) 0x4000001F)

typedef BOOL (WINAPI *t_WaitForDebugEvent)(LPDEBUG_EVENT lpDebugEvent,DWORD dwMilliseconds);
typedef BOOL (WINAPI *t_ContinueDebugEvent)(DWORD dwProcessId,DWORD dwThreadId,DWORD dwContinueStatus);

BOOL WINAPI HookedWaitForDebugEvent(LPDEBUG_EVENT lpDebugEvent,DWORD dwMilliseconds);
BOOL WINAPI HookedContinueDebugEvent(DWORD dwProcessId,DWORD dwThreadId,DWORD dwContinueStatus);

void HookDebugLoop();

