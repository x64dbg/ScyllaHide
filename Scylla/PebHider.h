#pragma once

#include <windows.h>

#define PEB_PATCH_BeingDebugged 0x00000001
#define PEB_PATCH_NtGlobalFlag 0x00000002
#define PEB_PATCH_HeapFlags 0x00000004
#define PEB_PATCH_StartUpInfo 0x00000008
//#define PEB_PATCH_BeingDebugged      0x00000010

bool FixPebBeingDebugged(HANDLE hProcess, bool SetToNull);
bool FixPebInProcess(HANDLE hProcess, DWORD EnableFlags);
