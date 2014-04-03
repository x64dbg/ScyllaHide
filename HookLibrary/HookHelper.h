#pragma once

#include <windows.h>

bool IsValidHandle(HANDLE hHandle);
bool IsValidThreadHandle(HANDLE hThread);
bool IsValidProcessHandle(HANDLE hProcess);
DWORD GetExplorerProcessId();
DWORD GetCsrssProcessId();
DWORD GetProcessIdByName(const WCHAR * processName);
bool IsProcessBad(const WCHAR * name, int nameSizeInBytes);
bool IsAtleastVista();

DWORD GetProcessIdByProcessHandle(HANDLE hProcess);
DWORD GetThreadIdByThreadHandle(HANDLE hThread);
DWORD GetProcessIdByThreadHandle(HANDLE hThread);

bool wcsistr(const wchar_t *s, const wchar_t *t);

