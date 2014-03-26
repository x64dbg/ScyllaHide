#pragma once

#include <windows.h>


typedef BOOL  (WINAPI * t_BlockInput)(BOOL fBlockIt);
typedef DWORD (WINAPI * t_OutputDebugStringA)(LPCSTR lpOutputString);
typedef DWORD (WINAPI * t_OutputDebugStringW)(LPCWSTR lpOutputString);
//WIN 7 X64: OutputDebugStringW -> OutputDebugStringA



NTSTATUS NTAPI HookedNtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
NTSTATUS NTAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI HookedNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
