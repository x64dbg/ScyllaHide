#pragma once

#include <windows.h>
#include "_plugins.h"

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
DLL_EXPORT bool plugstop();
DLL_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct);

#ifdef __cplusplus
}
#endif

//scyllahide definitions

#define MENU_OPTIONS 0
#define MENU_PROFILES 1

typedef void (__cdecl * t_LogWrapper)(const WCHAR * format, ...);

static void cbMenuEntry(CBTYPE cbType, void* callbackInfo);
static void cbDebugloop(CBTYPE cbType, void* callbackInfo);
void LogErrorWrapper(const WCHAR * format, ...);
void LogWrapper(const WCHAR * format, ...);