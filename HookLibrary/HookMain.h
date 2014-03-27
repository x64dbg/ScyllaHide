#pragma once

#include <windows.h>

typedef BOOL(WINAPI * t_DllMain)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
typedef FARPROC(WINAPI * t_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef HMODULE(WINAPI * t_GetModuleHandleA)(LPCSTR lpModuleName);
typedef HMODULE(WINAPI * t_LoadLibraryA)(LPCSTR lpFileName);

typedef struct _HOOK_DLL_EXCHANGE {
	HMODULE hNtdll;
	HMODULE hkernel32;
	HMODULE hkernelBase;
	HMODULE hUser32;
	t_GetProcAddress fGetProcAddress;
	t_GetModuleHandleA fGetModuleHandleA;
	t_LoadLibraryA fLoadLibraryA;
} HOOK_DLL_EXCHANGE;


#define HOOK_ERROR_SUCCESS 0
#define HOOK_ERROR_RESOLVE_IMPORT 1
#define HOOK_ERROR_DLLMAIN 2
#define HOOK_ERROR_PEHEADER 3

