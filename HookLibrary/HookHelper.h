#pragma once

#include "..\ntdll\ntdll.h"

bool IsValidHandle(HANDLE hHandle);
bool IsValidThreadHandle(HANDLE hThread);
bool IsValidProcessHandle(HANDLE hProcess);
DWORD GetExplorerProcessId();
DWORD GetCsrssProcessId();
DWORD GetProcessIdByName(const WCHAR * processName);
bool IsProcessBad(PUNICODE_STRING process);
bool IsAtleastVista();

DWORD GetProcessIdByProcessHandle(HANDLE hProcess);
DWORD GetThreadIdByThreadHandle(HANDLE hThread);
DWORD GetProcessIdByThreadHandle(HANDLE hThread);

bool wcsistr(const wchar_t *s, const wchar_t *t);

bool IsWindowNameBad(PUNICODE_STRING lpszWindow);
bool IsWindowClassBad(PUNICODE_STRING lpszClass);

size_t _wcslen(const wchar_t* sc);
size_t _strlen(const char* sc);

int ThreadDebugContextFindFreeSlotIndex();
int ThreadDebugContextFindExistingSlotIndex();
void ThreadDebugContextRemoveEntry(const int index);
void ThreadDebugContextSaveContext(const int index, const PCONTEXT ThreadContext);

void IncreaseSystemTime(LPSYSTEMTIME lpTime);
