#pragma once

#include <windows.h>
#include "ntdll.h"

typedef BOOL(WINAPI * t_DllMain)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
typedef void  (WINAPI * t_GetSystemTime)(LPSYSTEMTIME lpSystemTime); //Kernel32.dll
typedef void  (WINAPI * t_GetLocalTime)(LPSYSTEMTIME lpSystemTime); //Kernel32.dll
typedef DWORD(WINAPI * t_timeGetTime)(void); //Winmm.dll
typedef DWORD(WINAPI * t_GetTickCount)(void); //Kernel32.dll
typedef BOOL(WINAPI * t_QueryPerformanceCounter)(LARGE_INTEGER *lpPerformanceCount); //Kernel32.dll
typedef BOOL(WINAPI * t_BlockInput)(BOOL fBlockIt); //user32.dll
typedef DWORD(WINAPI * t_OutputDebugStringA)(LPCSTR lpOutputString); //Kernel32.dll
typedef DWORD(WINAPI * t_OutputDebugStringW)(LPCWSTR lpOutputString); //Kernel32.dll
//WIN 7 X64: OutputDebugStringW -> OutputDebugStringA

#pragma pack(push)
#pragma pack(1)

typedef struct _HOOK_DLL_EXCHANGE {
    HMODULE hDllImage;
    HMODULE hNtdll;
    HMODULE hkernel32;
    HMODULE hkernelBase;
    HMODULE hUser32;

    BOOLEAN EnablePebHiding;

    BOOLEAN EnableBlockInputHook;
    BOOLEAN EnableGetTickCountHook;
    BOOLEAN EnableOutputDebugStringHook;

    BOOLEAN EnableNtSetInformationThreadHook;
    BOOLEAN EnableNtQuerySystemInformationHook;
    BOOLEAN EnableNtQueryInformationProcessHook;
    BOOLEAN EnableNtQueryObjectHook;
    BOOLEAN EnableNtYieldExecutionHook;
    BOOLEAN EnableNtCloseHook;

    //Protect and Hide Hardware Breakpoints
    BOOLEAN EnableNtGetContextThreadHook;
    BOOLEAN EnableNtSetContextThreadHook;
    BOOLEAN EnableNtContinueHook;
    BOOLEAN EnableKiUserExceptionDispatcherHook;

    //Native User32.dll functions, not exported
    DWORD NtUserQueryWindowRVA;
    DWORD NtUserBuildHwndListRVA;
    DWORD NtUserFindWindowExRVA;

    BOOLEAN EnableNtUserQueryWindowHook;
    BOOLEAN EnableNtUserBuildHwndListHook;
    BOOLEAN EnableNtUserFindWindowExHook;
    BOOLEAN EnableNtSetDebugFilterStateHook;



    t_NtSetInformationThread dNtSetInformationThread;
    t_NtQuerySystemInformation dNtQuerySystemInformation;
    t_NtSetInformationProcess dNtSetInformationProcess;
    t_NtQueryInformationProcess dNtQueryInformationProcess;
    t_NtQueryObject dNtQueryObject;
    t_NtYieldExecution dNtYieldExecution;
    t_NtGetContextThread dNtGetContextThread;
    t_NtSetContextThread dNtSetContextThread;
    t_KiUserExceptionDispatcher dKiUserExceptionDispatcher;
    t_NtContinue dNtContinue;
    t_NtClose dNtClose;

    t_GetTickCount dGetTickCount;
    t_BlockInput dBlockInput;

    t_NtUserFindWindowEx dNtUserFindWindowEx;
	t_NtUserBuildHwndList dNtUserBuildHwndList;
	t_NtUserQueryWindow dNtUserQueryWindow;
	t_NtUserQueryWindow NtUserQueryWindow;
	//t_NtUserGetClassName dNtUserGetClassName;

	DWORD dwProtectedProcessId;
	BOOLEAN EnableProtectProcessId;
} HOOK_DLL_EXCHANGE;

#pragma pack(pop)

#define HOOK_ERROR_SUCCESS 0
#define HOOK_ERROR_RESOLVE_IMPORT 1
#define HOOK_ERROR_DLLMAIN 2
#define HOOK_ERROR_PEHEADER 3

