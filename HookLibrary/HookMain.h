#pragma once

#include <ntdll/ntdll.h>

typedef BOOL(WINAPI * t_DllMain)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

typedef void  (WINAPI * t_GetSystemTime)(LPSYSTEMTIME lpSystemTime); //Kernel32.dll / kernelbase
typedef void  (WINAPI * t_GetLocalTime)(LPSYSTEMTIME lpSystemTime); //Kernel32.dll / kernelbase
typedef DWORD(WINAPI * t_timeGetTime)(void); //Winmm.dll -> sometimes GetTickCount
typedef DWORD(WINAPI * t_GetTickCount)(void); //Kernel32.dll / kernelbase
typedef ULONGLONG(WINAPI * t_GetTickCount64)(void);
typedef BOOL(WINAPI * t_QueryPerformanceCounter)(LARGE_INTEGER *lpPerformanceCount); //Kernel32.dll -> ntdll.RtlQueryPerformanceCounter -> NO NATIVE CALL
typedef BOOL(WINAPI * t_QueryPerformanceFrequency)(LARGE_INTEGER *lpFrequency); //kernel32.dll -> ntdll.RtlQueryPerformanceFrequency -> ntdll.ZwQueryPerformanceCounter

typedef DWORD(WINAPI * t_OutputDebugStringA)(LPCSTR lpOutputString); //Kernel32.dll
typedef DWORD(WINAPI * t_OutputDebugStringW)(LPCWSTR lpOutputString); //Kernel32.dll
//WIN 7 X64: OutputDebugStringW -> OutputDebugStringA

#define MAX_NATIVE_HOOKS 32

#pragma pack(push, 1)
typedef struct _HOOK_NATIVE_CALL32 {
    DWORD eaxValue;
    DWORD ecxValue;
    PVOID hookedFunction;
} HOOK_NATIVE_CALL32;

typedef struct _HOOK_DLL_DATA {
    HMODULE hDllImage;

    BOOLEAN EnablePebBeingDebugged;
    BOOLEAN EnablePebHeapFlags;
    BOOLEAN EnablePebNtGlobalFlag;
    BOOLEAN EnablePebStartupInfo;

    BOOLEAN EnableOutputDebugStringHook;

    BOOLEAN EnableNtSetInformationThreadHook;
    BOOLEAN EnableNtQuerySystemInformationHook;
    BOOLEAN EnableNtQueryInformationProcessHook;
	BOOLEAN EnableNtSetInformationProcessHook;
    BOOLEAN EnableNtQueryObjectHook;
    BOOLEAN EnableNtYieldExecutionHook;
    BOOLEAN EnableNtCloseHook;

    BOOLEAN EnablePreventThreadCreation;
    BOOLEAN EnableNtCreateThreadExHook;

    //Protect and Hide Hardware Breakpoints
    BOOLEAN EnableNtGetContextThreadHook;
    BOOLEAN EnableNtSetContextThreadHook;
    BOOLEAN EnableNtContinueHook;
    BOOLEAN EnableKiUserExceptionDispatcherHook;

    //Native user32.dll/win32u.dll functions
    ULONG_PTR NtUserBlockInputVA;
    ULONG_PTR NtUserQueryWindowVA;
    ULONG_PTR NtUserBuildHwndListVA;
    ULONG_PTR NtUserFindWindowExVA;
    ULONG_PTR NtUserGetClassNameVA;
    ULONG_PTR NtUserInternalGetWindowTextVA;

    BOOLEAN EnableNtUserBlockInputHook;
    BOOLEAN EnableNtUserQueryWindowHook;
    BOOLEAN EnableNtUserBuildHwndListHook;
    BOOLEAN EnableNtUserFindWindowExHook;
    BOOLEAN EnableNtSetDebugFilterStateHook;

	BOOLEAN EnableGetTickCountHook;
	BOOLEAN EnableGetTickCount64Hook;
	BOOLEAN EnableGetLocalTimeHook;
	BOOLEAN EnableGetSystemTimeHook;
	BOOLEAN EnableNtQuerySystemTimeHook;
	BOOLEAN EnableNtQueryPerformanceCounterHook;

	//special
	BOOLEAN EnableMalwareRunPeUnpacker;
	//t_NtWriteVirtualMemory dNtWriteVirtualMemory;
	//DWORD NtWriteVirtualMemoryBackupSize;
	t_NtResumeThread dNtResumeThread;
	DWORD NtResumeThreadBackupSize;

	t_NtSetDebugFilterState dNtSetDebugFilterState;
	DWORD NtSetDebugFilterStateBackupSize;
    t_NtSetInformationThread dNtSetInformationThread;
    DWORD NtSetInformationThreadBackupSize;
    t_NtQuerySystemInformation dNtQuerySystemInformation;
    DWORD NtQuerySystemInformationBackupSize;
    t_NtSetInformationProcess dNtSetInformationProcess;
    DWORD NtSetInformationProcessBackupSize;
    t_NtQueryInformationProcess dNtQueryInformationProcess;
    DWORD NtQueryInformationProcessBackupSize;
    t_NtQueryObject dNtQueryObject;
    DWORD NtQueryObjectBackupSize;
    t_NtYieldExecution dNtYieldExecution;
    DWORD NtYieldExecutionBackupSize;
    t_NtGetContextThread dNtGetContextThread;
    DWORD NtGetContextThreadBackupSize;
    t_NtSetContextThread dNtSetContextThread;
    DWORD NtSetContextThreadBackupSize;
    t_KiUserExceptionDispatcher dKiUserExceptionDispatcher;
    DWORD KiUserExceptionDispatcherBackupSize;
    t_NtContinue dNtContinue;
    DWORD NtContinueBackupSize;
    t_NtClose dNtClose;
    DWORD NtCloseBackupSize;
    t_NtDuplicateObject dNtDuplicateObject;
    DWORD NtDuplicateObjectBackupSize;

    t_NtCreateThreadEx dNtCreateThreadEx; //only since vista
    DWORD NtCreateThreadExBackupSize;
    t_NtCreateThread dNtCreateThread;
    DWORD NtCreateThreadBackupSize;

	/////////////////////////////////////////////////////////
	t_GetTickCount dGetTickCount;
	DWORD GetTickCountBackupSize;
	t_GetTickCount64 dGetTickCount64;
	DWORD GetTickCount64BackupSize;

	t_GetLocalTime dGetLocalTime;
	DWORD GetLocalTimeBackupSize;
	t_GetSystemTime dGetSystemTime;
	DWORD GetSystemTimeBackupSize;

	t_NtQuerySystemTime dNtQuerySystemTime;
	DWORD NtQuerySystemTimeBackupSize;
	t_NtQueryPerformanceCounter dNtQueryPerformanceCounter;
	DWORD NtQueryPerformanceCounterBackupSize;
	/////////////////////////////////////////////////////////


    t_OutputDebugStringA dOutputDebugStringA;
    DWORD OutputDebugStringABackupSize;

    t_NtUserBlockInput dNtUserBlockInput;
    DWORD NtUserBlockInputBackupSize;
    t_NtUserFindWindowEx dNtUserFindWindowEx;
    DWORD NtUserFindWindowExBackupSize;
    t_NtUserBuildHwndList /*or t_NtUserBuildHwndList_Eight*/ dNtUserBuildHwndList;
    DWORD NtUserBuildHwndListBackupSize;
    t_NtUserQueryWindow dNtUserQueryWindow;
    DWORD NtUserQueryWindowBackupSize;


    t_NtUserQueryWindow NtUserQueryWindow;
    t_NtUserGetClassName NtUserGetClassName;
    t_NtUserInternalGetWindowText NtUserInternalGetWindowText;

    DWORD dwProtectedProcessId;
    BOOLEAN EnableProtectProcessId;


    BOOLEAN isNtdllHooked;
    BOOLEAN isKernel32Hooked;
    BOOLEAN isUserDllHooked;

#ifndef _WIN64
    HOOK_NATIVE_CALL32 HookNative[MAX_NATIVE_HOOKS];
    PVOID NativeCallContinue;
#endif
} HOOK_DLL_DATA;
#pragma pack(pop)

#define HOOK_ERROR_SUCCESS 0
#define HOOK_ERROR_RESOLVE_IMPORT 1
#define HOOK_ERROR_DLLMAIN 2
#define HOOK_ERROR_PEHEADER 3

