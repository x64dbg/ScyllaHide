#pragma once
#include <windows.h>
#include "..\HookLibrary\HookMain.h"

bool ApplyPEBPatch(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess, DWORD enableFlags);
bool ApplyHook(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase);
void RestoreHooks(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess);