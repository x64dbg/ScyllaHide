#pragma once

#include <ntdll/ntdll.h>

FORCEINLINE ULONG NTAPI RtlNtMajorVersion()
{
	return *(PULONG)(0x7FFE0000 + 0x26C);
}

FORCEINLINE ULONG NTAPI RtlNtMinorVersion()
{
	return *(PULONG)(0x7FFE0000 + 0x270);
}

FORCEINLINE ULONG NTAPI RtlGetTickCount()
{
	return (ULONG)(*(PULONG64)(0x7FFE0000 + 0x320) * *(PULONG)(0x7FFE0000 + 0x4) >> 24);
}

bool HasDebugPrivileges(HANDLE hProcess);
bool IsWow64Process(HANDLE ProcessHandle);
NTSTATUS InstallInstrumentationCallbackHook(HANDLE ProcessHandle, BOOLEAN Remove);
DWORD GetExplorerProcessId();
DWORD GetProcessIdByName(PUNICODE_STRING processName);
bool IsProcessNameBad(PUNICODE_STRING processName);

DWORD GetProcessIdByProcessHandle(HANDLE hProcess);
DWORD GetProcessIdByThreadHandle(HANDLE hThread);

bool RtlUnicodeStringContains(PUNICODE_STRING Str, PUNICODE_STRING SubStr, BOOLEAN CaseInsensitive);

bool IsWindowNameBad(PUNICODE_STRING windowName);
bool IsWindowClassNameBad(PUNICODE_STRING className);
bool IsWindowBad(HWND hWnd);
bool IsObjectTypeBad(USHORT objectTypeIndex);

int ThreadDebugContextFindFreeSlotIndex();
int ThreadDebugContextFindExistingSlotIndex();
void ThreadDebugContextRemoveEntry(const int index);
void ThreadDebugContextSaveContext(const int index, const PCONTEXT ThreadContext);

void NTAPI RealGetSystemTime(PSYSTEMTIME lpSystemTime);
void NTAPI RealGetLocalTime(LPSYSTEMTIME lpSystemTime);
void IncreaseSystemTime(LPSYSTEMTIME lpTime);

void TerminateProcessByProcessId(DWORD dwProcess);
bool WriteMalwareToDisk(LPCVOID buffer, DWORD bufferSize, DWORD_PTR imagebase);
bool WriteMemoryToFile(const WCHAR * filename, LPCVOID buffer, DWORD bufferSize, DWORD_PTR imagebase);
void * GetPEBRemote(HANDLE hProcess);
void DumpMalware(DWORD dwProcessId);
