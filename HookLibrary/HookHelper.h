#pragma once

#include <windows.h>

bool IsValidHandle(HANDLE hHandle);
bool IsValidThreadHandle(HANDLE hThread);
bool IsValidProcessHandle(HANDLE hProcess);
DWORD GetProcessIdByProcessHandle(HANDLE hProcess);
DWORD GetExplorerProcessId();
DWORD GetCsrssProcessId();
DWORD GetProcessIdByName(const WCHAR * processName);
bool IsProcessBad(const WCHAR * name, int nameSizeInBytes);


