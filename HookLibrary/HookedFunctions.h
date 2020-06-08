#pragma once

#include <ntdll/ntdll.h>


#define STATUS_PRIVILEGE_NOT_HELD ((NTSTATUS)0xC0000061L)
#define STATUS_PORT_NOT_SET ((NTSTATUS)0xC0000353L)
#define STATUS_HANDLE_NOT_CLOSABLE ((NTSTATUS)0xC0000235L)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#define PROCESS_DEBUG_INHERIT 0x00000001 // default for a non-debugged process
#define PROCESS_NO_DEBUG_INHERIT 0x00000002 // default for a debugged process
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004

#ifndef _WIN64
#define NAKED __declspec(naked)
#else
#define NAKED
#endif

typedef struct _SAVE_DEBUG_REGISTERS
{
    DWORD dwThreadId;
    DWORD_PTR Dr0;
    DWORD_PTR Dr1;
    DWORD_PTR Dr2;
    DWORD_PTR Dr3;
    DWORD_PTR Dr6;
    DWORD_PTR Dr7;
} SAVE_DEBUG_REGISTERS;

//DbgBreakPoint

NTSTATUS NTAPI HookedNtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
NTSTATUS NTAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI HookedNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI HookedNtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI HookedNtYieldExecution();
NTSTATUS NTAPI HookedNtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
NTSTATUS NTAPI HookedNtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
NTSTATUS NTAPI HookedNtContinue(PCONTEXT ThreadContext, BOOLEAN RaiseAlert);
NTSTATUS NTAPI HookedNtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
NTSTATUS NTAPI HookedNtClose(HANDLE Handle);
NTSTATUS NTAPI HookedNtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);
NTSTATUS NTAPI HookedNtSetDebugFilterState(ULONG ComponentId, ULONG Level, BOOLEAN State);
NTSTATUS NTAPI HookedNtUserBuildHwndList(HDESK hDesktop, HWND hwndParent, BOOLEAN bChildren, ULONG dwThreadId, ULONG lParam, HWND* pWnd, PULONG pBufSize);
NTSTATUS NTAPI HookedNtUserBuildHwndList_Eight(HDESK hDesktop, HWND hwndParent, BOOLEAN bChildren, BOOLEAN bUnknownFlag, ULONG dwThreadId, ULONG lParam, HWND* pWnd, PULONG pBufSize);
NTSTATUS NTAPI HookedNtCreateThread(PHANDLE ThreadHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,HANDLE ProcessHandle,PCLIENT_ID ClientId,PCONTEXT ThreadContext,PINITIAL_TEB InitialTeb,BOOLEAN CreateSuspended);
NTSTATUS NTAPI HookedNtCreateThreadEx(PHANDLE ThreadHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,HANDLE ProcessHandle,PUSER_THREAD_START_ROUTINE StartRoutine,PVOID Argument,ULONG CreateFlags,ULONG_PTR ZeroBits,SIZE_T StackSize,SIZE_T MaximumStackSize,PPS_ATTRIBUTE_LIST AttributeList);
HANDLE NTAPI HookedNtUserQueryWindow(HWND hwnd, WINDOWINFOCLASS WindowInfo);
BOOL NTAPI HookedNtUserBlockInput(BOOL fBlockIt);


DWORD WINAPI HookedGetTickCount(void);
ULONGLONG WINAPI HookedGetTickCount64(void);
void WINAPI HookedGetLocalTime(LPSYSTEMTIME lpSystemTime);
void WINAPI HookedGetSystemTime(LPSYSTEMTIME lpSystemTime);
NTSTATUS WINAPI HookedNtQuerySystemTime(PLARGE_INTEGER SystemTime);
NTSTATUS NTAPI HookedNtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency);

DWORD WINAPI HookedOutputDebugStringA(LPCSTR lpOutputString);
#ifdef _WIN64
void NTAPI HandleKiUserExceptionDispatcher(PEXCEPTION_RECORD pExcptRec, PCONTEXT ContextFrame);
#else
VOID NTAPI HookedKiUserExceptionDispatcher();//(PEXCEPTION_RECORD pExcptRec, PCONTEXT ContextFrame);
#endif

HWND NTAPI HookedNtUserFindWindowEx(HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass, PUNICODE_STRING lpszWindow, DWORD dwType);

NTSTATUS NTAPI HookedNtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
