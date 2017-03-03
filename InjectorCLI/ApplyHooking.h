#pragma once
#include <windows.h>
#include "..\HookLibrary\HookMain.h"

void ApplyPEBPatch(HANDLE hProcess, DWORD flags);
bool ApplyHook(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase);
void RestoreHooks(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess);
