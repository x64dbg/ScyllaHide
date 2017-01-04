#pragma once

#include <windows.h>
#include <x64dbg/_plugins.h>

#ifndef DLL_EXPORT
#define DLL_EXPORT __declspec(dllexport)
#endif

//superglobal variables
extern int pluginHandle;
extern HWND hwndDlg;
extern int hMenu;

#ifdef __cplusplus
extern "C"
{
#endif

    DLL_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct);
    DLL_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct);

#ifdef __cplusplus
}
#endif

typedef void(__cdecl * t_LogWrapper)(const WCHAR * format, ...);
typedef void(__cdecl * t_AttachProcess)(DWORD dwPID);

static void cbMenuEntry(CBTYPE cbType, void* callbackInfo);
static void cbDebugloop(CBTYPE cbType, void* callbackInfo);
static void cbReset(CBTYPE cbType, void* callbackInfo);
void LogErrorWrapper(const WCHAR * format, ...);
void LogWrapper(const WCHAR * format, ...);
void AttachProcess(DWORD dwPID);
