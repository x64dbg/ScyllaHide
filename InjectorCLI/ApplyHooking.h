#pragma once
#include <windows.h>
#include "..\HookLibrary\HookMain.h"

void ApplyPEBPatch(HANDLE hProcess, DWORD flags);
void ApplyNtdllVersionPatch(HANDLE hProcess);
bool ApplyHook(HOOK_DLL_DATA * hdd, HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase);
void RestoreHooks(HOOK_DLL_DATA * hdd, HANDLE hProcess);
