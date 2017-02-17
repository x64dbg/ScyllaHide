#ifndef SCYLLAHIDE_GENERIC_PLUGIN_H
#define SCYLLAHIDE_GENERIC_PLUGIN_H

#include <windows.h>

#ifdef SCYLLAHIDEGENERICPLUGIN_EXPORTS
#define DLL_EXPORT extern "C" __declspec(dllexport)
#else
#define DLL_EXPORT extern "C" __declspec(dllimport)
#endif

typedef void(__cdecl * LOGWRAPPER)(const WCHAR * format, ...);

DLL_EXPORT void ScyllaHideInit(const WCHAR* Directory = NULL, LOGWRAPPER Logger = NULL, LOGWRAPPER ErrorLogger = NULL);
DLL_EXPORT void ScyllaHideReset();
DLL_EXPORT void ScyllaHideDebugLoop(const DEBUG_EVENT* DebugEvent);

#endif //SCYLLAHIDE_GENERIC_PLUGIN_H
